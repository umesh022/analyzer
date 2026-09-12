"""
Groq LLM Service
Handles: RCA generation (with optional CoT template injection),
         LLM pre-pass failure extraction, chat (streaming + single-shot).
No agentic loops — every call is a single, direct LLM request.
"""

import re
import os
import json
import logging
from typing import List, Dict, Optional, AsyncGenerator

from groq import Groq, AsyncGroq

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "groq/compound-mini"

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

def _strip_thinking(text: str) -> str:
    return _THINK_RE.sub("", text).strip()


# ── System Prompts ─────────────────────────────────────────────────────────────

ANALYST_SYSTEM_PROMPT = """You are an expert 3GPP protocol engineer and RCA (Root Cause Analysis) specialist with deep knowledge of:
- 3GPP specifications: TS 38.331 (NR RRC), TS 24.501 (5GS NAS), TS 38.413 (NGAP),
  TS 38.321 (MAC), TS 38.322 (RLC), TS 38.323 (PDCP), TS 36.331 (LTE RRC),
  TS 36.413 (S1AP), TS 23.501 (5G System Architecture)
- Protocol layers: RRC, NAS, MAC, RLC, PDCP, NGAP/S1AP, GTP, DIAMETER
- Radio failures: RLF, handover failures, authentication failures, bearer/PDU session issues
- Standard 3GPP call flows and message sequences

WHEN A CHAIN-OF-THOUGHT TEMPLATE IS PROVIDED:
- You MUST follow the analysis steps in the exact order given.
- For each step, explicitly state: what you found in the log, the 3GPP spec reference, and your conclusion.
- If a step's evidence is not present in the log, state "Not observed in log" and continue.
- After completing all CoT steps, provide an overall RCA conclusion.

WITHOUT A TEMPLATE:
- Structure your RCA: Executive Summary → Failure Analysis → Root Cause → Cascading Impact → Corrective Actions → Preventive Measures.

Always cite specific TS numbers and sections. Be technical and precise."""

COT_ANALYST_SYSTEM_PROMPT = """You are an expert 3GPP protocol engineer performing a structured Chain-of-Thought (CoT) Root Cause Analysis.

You have been given a specific analysis template to follow. Your job is to:
1. Follow EVERY step in the template sequentially — do not skip any step.
2. For each step, examine the log evidence and cite specific log lines or timestamps.
3. Reference the exact 3GPP specification (TS number and section) for each finding.
4. Apply the standard call flow to map where in the procedure the failure occurred.
5. Conclude with a precise root cause and actionable corrective steps.

Format your response with clear headings for each step.
Be technical, precise, and evidence-based. Do not speculate beyond what the log shows."""

PRE_PASS_SYSTEM_PROMPT = """You are a 3GPP log parser. Extract every failure, error, or anomaly from the log.

Output ONLY a valid JSON array — no explanation, no markdown fences, no extra text.
Each element:
{
  "line_number": <int or null>,
  "layer": "<RRC|NAS|MAC|RLC|PDCP|NGAP|S1AP|GTP|DIAMETER|UNKNOWN>",
  "failure_type": "<short name>",
  "cause": "<cause or null>",
  "spec_reference": "<3GPP TS ref or empty>",
  "description": "<one sentence>",
  "severity": "<CRITICAL|ERROR|WARNING|INFO>"
}
Output [] if genuinely no failures. Output ONLY the JSON array."""

CHAT_SYSTEM_PROMPT = """You are a log analysis assistant. Answer ONLY questions about the specific uploaded log.

You have: parsed failure points, failure chain analysis, RCA report, and the full raw log text.

RULES:
- Answer only from provided log data. Never invent.
- Quote exact log lines when asked about specific values (IMSI, IP, timestamps, parameters).
- If absent from log: say "This information is not present in the uploaded log."
- Cite line numbers when possible.
- No padding — concise, factual answers only."""


# ── Service ────────────────────────────────────────────────────────────────────

class GroqLLMService:

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.model   = os.getenv("GROQ_MODEL", _DEFAULT_MODEL)
        self._client:       Optional[Groq]      = None
        self._async_client: Optional[AsyncGroq] = None
        if not self.api_key:
            logger.warning("GROQ_API_KEY not set")
        else:
            logger.info(f"Groq ready: model={self.model}")

    def _get_client(self) -> Groq:
        if self._client is None:
            self._client = Groq(api_key=self.api_key)
        return self._client

    def _get_async_client(self) -> AsyncGroq:
        if self._async_client is None:
            self._async_client = AsyncGroq(api_key=self.api_key)
        return self._async_client

    # ── LLM Pre-pass ──────────────────────────────────────────────────────────

    def extract_failures_from_log(self, log_text: str) -> List[Dict]:
        if not self.api_key:
            return []
        prompt = ("Analyze this telecom log and extract all failures as JSON:\n\n"
                  f"LOG:\n{log_text[:12000]}")
        try:
            resp = self._get_client().chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": PRE_PASS_SYSTEM_PROMPT},
                          {"role": "user",   "content": prompt}],
                temperature=0.1, max_tokens=4096,
            )
            raw = _strip_thinking(resp.choices[0].message.content)
            raw = re.sub(r"```(?:json)?", "", raw).strip().strip("`")
            failures = json.loads(raw)
            if not isinstance(failures, list):
                raise ValueError("non-list")
            return [{"line_number": f.get("line_number"), "timestamp": None,
                     "layer": f.get("layer", "UNKNOWN"),
                     "failure_type": f.get("failure_type", "Unknown Failure"),
                     "cause": f.get("cause"),
                     "spec_reference": f.get("spec_reference", ""),
                     "description": f.get("description", ""),
                     "raw_line": f"[LLM-extracted] {f.get('failure_type','')}",
                     "severity": f.get("severity", "ERROR")}
                    for f in failures]
        except Exception as e:
            logger.warning(f"Pre-pass failed: {e}")
            return []

    # ── RCA Generation ─────────────────────────────────────────────────────────

    def generate_rca(self, failures: List[Dict], rag_context: str,
                     mcp_chain_analysis: Dict, log_snippet: str = "",
                     cot_prompt_block: str = "") -> str:
        """
        Generate RCA. If cot_prompt_block is provided, uses the CoT-specific
        system prompt and structures the request around the template steps.
        """
        if not self.api_key:
            return "⚠️ GROQ_API_KEY not configured."

        failure_summary = self._format_failures(failures)
        chain_text      = self._format_chain(mcp_chain_analysis)
        detected_by     = ("LLM pre-pass" if any(
            f.get("raw_line", "").startswith("[LLM-extracted]") for f in failures
        ) else "regex parser")

        # ── CoT mode: wrap the prompt differently ──────────────────────────────
        if cot_prompt_block:
            system_prompt = COT_ANALYST_SYSTEM_PROMPT
            prompt = f"""## 3GPP Log RCA — Chain-of-Thought Analysis
Failures detected by: {detected_by}

{cot_prompt_block}

---

### Detected Failures ({len(failures)} total)
{failure_summary}

### Failure Chain (MCP Analysis)
{chain_text}

### 3GPP Specification Context (RAG)
{rag_context if rag_context else "Not available — proceed from log evidence and 3GPP knowledge."}

### Raw Log (first 8000 chars)
```
{log_snippet[:8000]}
```

---

## YOUR TASK
Follow the Chain-of-Thought template steps above IN ORDER.

For each step use this format:

### Step N: [Step Title]
**3GPP Reference:** [spec]
**Evidence in Log:** [exact log lines or timestamps, or "Not observed"]
**Finding:** [your technical conclusion for this step]

After all steps, provide:
### Overall Root Cause Conclusion
### Recommended Corrective Actions
### Preventive Measures
"""
        else:
            # ── Standard mode (no CoT) ─────────────────────────────────────────
            system_prompt = ANALYST_SYSTEM_PROMPT
            prompt = f"""## 3GPP Log Analysis
Failures detected by: {detected_by}

### Detected Failures ({len(failures)} total)
{failure_summary}

### Failure Chain Analysis
{chain_text}

### 3GPP Specification Context (RAG)
{rag_context if rag_context else "Not available."}

### Raw Log (first 8000 chars)
```
{log_snippet[:8000]}
```

## Task
Provide a comprehensive RCA:
1. **Executive Summary** — What failed, which layer, approximate time
2. **Failure Point Analysis** — Each failure with 3GPP spec reference
3. **Root Cause** — Primary root cause with technical evidence
4. **Cascading Impact** — How failures propagated across layers
5. **Recommended Corrective Actions** — Specific fixes with config examples
6. **Preventive Measures** — How to prevent recurrence
"""

        try:
            resp = self._get_client().chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system_prompt},
                          {"role": "user",   "content": prompt}],
                temperature=0.3,
                max_tokens=4096,
            )
            return _strip_thinking(resp.choices[0].message.content)
        except Exception as e:
            logger.error(f"RCA generation failed: {e}")
            return f"❌ LLM Error: {str(e)}"

    # ── Chat ───────────────────────────────────────────────────────────────────

    async def chat(self, messages: List[Dict], rag_context: str = "",
                   analysis_context: str = "") -> str:
        if not self.api_key:
            return "⚠️ GROQ_API_KEY not configured."
        full = self._build_messages(messages, rag_context, analysis_context)
        try:
            resp = await self._get_async_client().chat.completions.create(
                model=self.model, messages=full,
                temperature=0.6, max_tokens=2048,
            )
            return _strip_thinking(resp.choices[0].message.content)
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return f"❌ LLM Error: {str(e)}"

    async def stream_chat(self, messages: List[Dict], rag_context: str = "",
                          analysis_context: str = "") -> AsyncGenerator[str, None]:
        if not self.api_key:
            yield "⚠️ GROQ_API_KEY not configured."
            return
        full = self._build_messages(messages, rag_context, analysis_context)
        try:
            stream = await self._get_async_client().chat.completions.create(
                model=self.model, messages=full,
                temperature=0.6, max_tokens=2048, stream=True,
            )
            buf, in_think = "", False
            async for chunk in stream:
                delta = chunk.choices[0].delta.content
                if not delta:
                    continue
                buf += delta
                while True:
                    if in_think:
                        end = buf.find("</think>")
                        if end == -1:
                            buf = ""; break
                        buf = buf[end + len("</think>"):]; in_think = False
                    else:
                        start = buf.find("<think>")
                        if start == -1:
                            if buf: yield buf; buf = ""
                            break
                        if start > 0: yield buf[:start]
                        buf = buf[start + len("<think>"):]; in_think = True
            if buf and not in_think:
                yield buf
        except Exception as e:
            logger.error(f"stream_chat failed: {e}")
            yield f"❌ LLM Streaming Error: {str(e)}"

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _build_messages(self, messages, rag_context, analysis_context):
        system = CHAT_SYSTEM_PROMPT
        if rag_context:
            system += f"\n\n{rag_context}"
        if analysis_context:
            system += f"\n\n### Current Analysis Context\n{analysis_context}"
        return [{"role": "system", "content": system}] + messages

    def _format_failures(self, failures: List[Dict]) -> str:
        if not failures:
            return "No failures detected."
        lines = [
            f"{i}. [{f.get('layer')}] {f.get('failure_type')} "
            f"(Line {f.get('line_number') or 'N/A'}, Cause: {f.get('cause') or 'N/A'}) "
            f"— Spec: {f.get('spec_reference') or 'N/A'}"
            for i, f in enumerate(failures[:20], 1)
        ]
        if len(failures) > 20:
            lines.append(f"  … and {len(failures) - 20} more")
        return "\n".join(lines)

    def _format_chain(self, chain_data: Dict) -> str:
        if not chain_data or not chain_data.get("chains"):
            return "No cascading failure chains detected."
        lines = [
            f"Root Layer: {chain_data.get('root_layer', 'Unknown')}",
            f"Affected: {', '.join(chain_data.get('affected_layers', []))}",
        ]
        for c in chain_data.get("chains", []):
            lines.append(f"  • {c.get('chain')}: {c.get('description')}")
            lines.append(f"    Root: {c.get('likely_root')}")
        return "\n".join(lines)


# ── Singleton ──────────────────────────────────────────────────────────────────

_llm_service: Optional[GroqLLMService] = None


def get_llm_service() -> GroqLLMService:
    global _llm_service
    if _llm_service is None:
        _llm_service = GroqLLMService()
    return _llm_service
