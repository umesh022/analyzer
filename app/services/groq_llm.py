"""
Groq LLM Service
Used for RCA generation, LLM pre-pass failure extraction, and chat.
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

# Strip <think>…</think> blocks (Qwen3 chain-of-thought leakage)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

def _strip_thinking(text: str) -> str:
    return _THINK_RE.sub("", text).strip()


# ── System Prompts ─────────────────────────────────────────────────────────────

ANALYST_SYSTEM_PROMPT = """You are an expert 3GPP protocol engineer and RCA (Root Cause Analysis) specialist.
You have deep knowledge of:
- 3GPP specifications: TS 38.331 (NR RRC), TS 24.501 (5GS NAS), TS 38.413 (NGAP),
  TS 38.321 (MAC), TS 38.322 (RLC), TS 38.323 (PDCP), TS 36.331 (LTE RRC),
  TS 36.413 (S1AP), TS 23.501 (5G System)
- Protocol stack: RRC, NAS, MAC, RLC, PDCP, NGAP/S1AP, GTP
- Radio network failures: RLF, handover failures, authentication failures, bearer setup failures
- Root cause analysis methodology for telecom networks

When analyzing logs:
1. Identify the failure type and affected protocol layer
2. Reference the specific 3GPP specification and section
3. Provide the root cause based on the failure indicators
4. Suggest corrective actions with technical specifics
5. Identify cascading failures across protocol layers

Always be precise, technical, and reference 3GPP specs by TS number and section.
Structure your RCA: Failure Summary → Root Cause → Specification Reference → Recommended Actions."""

PRE_PASS_SYSTEM_PROMPT = """You are a 3GPP log parser assistant. Your ONLY job is to read raw
telecom log text and identify every failure, error, or anomaly event present.

Output ONLY a valid JSON array — no explanation, no markdown fences, no extra text.
Each element must have exactly these fields:
{
  "line_number": <integer or null>,
  "layer": "<RRC|NAS|MAC|RLC|PDCP|NGAP|S1AP|GTP|DIAMETER|UNKNOWN>",
  "failure_type": "<short descriptive name>",
  "cause": "<cause value or null>",
  "spec_reference": "<3GPP TS reference or empty string>",
  "description": "<one sentence technical description>",
  "severity": "<CRITICAL|ERROR|WARNING|INFO>"
}

Rules:
- Include ALL failures, errors, warnings, anomalies you see.
- For each line that indicates a problem, produce one JSON object.
- Map the failure to the correct 3GPP protocol layer.
- If the cause is explicitly stated in the log, extract it exactly.
- Output [] if there are genuinely no failures in the log.
- Do NOT output anything except the JSON array."""

CHAT_SYSTEM_PROMPT = """You are a log analysis assistant. Your job is to answer questions about
the specific log that was uploaded and analyzed in this session.

You have access to:
1. The parsed failure points (layer, cause, spec reference, line number)
2. The failure chain analysis and RCA report
3. The FULL RAW LOG TEXT — read this carefully to answer any question about log content

RULES:
- Answer ONLY from the log data provided in the context below. Do not invent anything not present.
- If the question asks about something in the raw log (e.g. IMSI, IP address, timestamp, parameter
  value), read the raw log text and extract the exact value. Quote the relevant log line.
- If a value is not present anywhere in the log, say exactly:
  "This information is not present in the uploaded log."
- Always cite the line number or log line when giving a specific answer.
- Do not answer questions unrelated to the uploaded log.
- Keep answers concise and factual. No padding."""


# ── Service ────────────────────────────────────────────────────────────────────

class GroqLLMService:
    """
    Groq-hosted LLM client.
    Environment variables:
      GROQ_API_KEY — required
      GROQ_MODEL   — model ID (default: groq/compound-mini)
    """

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.model   = os.getenv("GROQ_MODEL", _DEFAULT_MODEL)
        self._client:       Optional[Groq]      = None
        self._async_client: Optional[AsyncGroq] = None

        if not self.api_key:
            logger.warning("GROQ_API_KEY not set — LLM calls will fail")
        else:
            logger.info(f"Groq LLM ready: model={self.model}")

    # ── Client factories ───────────────────────────────────────────────────────

    def _get_client(self) -> Groq:
        if self._client is None:
            self._client = Groq(api_key=self.api_key)
        return self._client

    def _get_async_client(self) -> AsyncGroq:
        if self._async_client is None:
            self._async_client = AsyncGroq(api_key=self.api_key)
        return self._async_client

    # ── LLM Pre-pass Failure Extraction ───────────────────────────────────────

    def extract_failures_from_log(self, log_text: str) -> List[Dict]:
        """
        Task 2: LLM pre-pass — called by the pipeline when regex finds 0 failures.
        Sends the full log (up to 12 000 chars) to the LLM and asks it to return
        structured failure data as a JSON array.
        Returns a list of failure dicts compatible with the rest of the pipeline.
        """
        if not self.api_key:
            return []

        # Use a generous slice — compound-mini handles 8k context well
        log_slice = log_text[:12000]

        prompt = (
            "Analyze the following telecom log and extract all failures, errors, "
            "and anomalies as a JSON array per the schema in your instructions.\n\n"
            f"LOG:\n{log_slice}"
        )

        try:
            response = self._get_client().chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": PRE_PASS_SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.1,   # low temp — we need deterministic JSON
                max_tokens=4096,
            )
            raw = _strip_thinking(response.choices[0].message.content)

            # Clean up: strip markdown fences if the model added them anyway
            raw = re.sub(r"```(?:json)?", "", raw).strip().strip("`")

            failures = json.loads(raw)
            if not isinstance(failures, list):
                raise ValueError("LLM returned non-list JSON")

            # Normalise — ensure every dict has required keys and add raw_line
            normalised = []
            for f in failures:
                normalised.append({
                    "line_number":    f.get("line_number"),
                    "timestamp":      None,
                    "layer":          f.get("layer", "UNKNOWN"),
                    "failure_type":   f.get("failure_type", "Unknown Failure"),
                    "cause":          f.get("cause"),
                    "spec_reference": f.get("spec_reference", ""),
                    "description":    f.get("description", ""),
                    "raw_line":       f"[LLM-extracted] {f.get('failure_type','')}",
                    "severity":       f.get("severity", "ERROR"),
                })

            logger.info(f"LLM pre-pass extracted {len(normalised)} failures")
            return normalised

        except json.JSONDecodeError as e:
            logger.warning(f"LLM pre-pass JSON parse failed: {e} — raw={raw[:200]}")
            return []
        except Exception as e:
            logger.error(f"LLM pre-pass failed: {e}")
            return []

    # ── RCA Generation (sync) ──────────────────────────────────────────────────

    def generate_rca(self, failures: List[Dict], rag_context: str,
                     mcp_chain_analysis: Dict, log_snippet: str = "") -> str:
        """Generate a full Root Cause Analysis report."""
        if not self.api_key:
            return "⚠️ GROQ_API_KEY not configured. Please set it in your .env file."

        failure_summary = self._format_failures(failures)
        chain_text      = self._format_chain(mcp_chain_analysis)
        detected_by     = "LLM pre-pass" if any(
            f.get("raw_line", "").startswith("[LLM-extracted]")
            for f in failures
        ) else "regex parser"

        # Task 3: increased log snippet to 8000 chars
        prompt = f"""## 3GPP Log Analysis Request
(Failures detected by: {detected_by})

### Detected Failures ({len(failures)} total)
{failure_summary}

### Failure Chain Analysis
{chain_text}

### Relevant 3GPP Specification Context (RAG)
{rag_context if rag_context else "Not available."}

### Raw Log (first 8000 chars)
```
{log_snippet[:8000]}
```

## Task
Provide a comprehensive Root Cause Analysis (RCA) structured as follows:

1. **Executive Summary** — What failed, in which layer, and approximate time
2. **Failure Point Analysis** — Each failure with 3GPP spec reference (TS number + section)
3. **Root Cause** — Primary root cause with technical evidence from the log
4. **Cascading Impact** — How failures propagated across protocol layers
5. **Recommended Corrective Actions** — Specific, actionable fixes with configuration examples
6. **Preventive Measures** — How to prevent recurrence

Be precise. Reference specific 3GPP specs. Base your analysis only on evidence in this log.
"""

        try:
            response = self._get_client().chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.3,
                max_tokens=4096,
            )
            return _strip_thinking(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Groq RCA generation failed: {e}")
            return f"❌ LLM Error during RCA generation: {str(e)}"

    # ── Chat (async, single-shot) ──────────────────────────────────────────────

    async def chat(self, messages: List[Dict], rag_context: str = "",
                   analysis_context: str = "") -> str:
        if not self.api_key:
            return "⚠️ GROQ_API_KEY not configured. Please set it in your .env file."
        full_messages = self._build_messages(messages, rag_context, analysis_context)
        try:
            response = await self._get_async_client().chat.completions.create(
                model=self.model,
                messages=full_messages,
                temperature=0.6,
                max_tokens=2048,
            )
            return _strip_thinking(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Groq chat failed: {e}")
            return f"❌ LLM Error: {str(e)}"

    # ── Streaming Chat (async) ─────────────────────────────────────────────────

    async def stream_chat(self, messages: List[Dict], rag_context: str = "",
                          analysis_context: str = "") -> AsyncGenerator[str, None]:
        if not self.api_key:
            yield "⚠️ GROQ_API_KEY not configured."
            return

        full_messages = self._build_messages(messages, rag_context, analysis_context)
        try:
            stream = await self._get_async_client().chat.completions.create(
                model=self.model,
                messages=full_messages,
                temperature=0.6,
                max_tokens=2048,
                stream=True,
            )
            buffer   = ""
            in_think = False
            async for chunk in stream:
                delta = chunk.choices[0].delta.content
                if not delta:
                    continue
                buffer += delta
                while True:
                    if in_think:
                        end = buffer.find("</think>")
                        if end == -1:
                            buffer = ""
                            break
                        buffer   = buffer[end + len("</think>"):]
                        in_think = False
                    else:
                        start = buffer.find("<think>")
                        if start == -1:
                            if buffer:
                                yield buffer
                                buffer = ""
                            break
                        if start > 0:
                            yield buffer[:start]
                        buffer   = buffer[start + len("<think>"):]
                        in_think = True
            if buffer and not in_think:
                yield buffer
        except Exception as e:
            logger.error(f"Groq stream_chat failed: {e}")
            yield f"❌ LLM Streaming Error: {str(e)}"

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_messages(self, messages, rag_context, analysis_context):
        system = CHAT_SYSTEM_PROMPT
        if rag_context:
            system += f"\n\n{rag_context}"
        if analysis_context:
            system += f"\n\n### Current Analysis Context\n{analysis_context}"
        return [{"role": "system", "content": system}] + messages

    def _format_failures(self, failures: List[Dict]) -> str:
        if not failures:
            return "No failures detected by regex or LLM pre-pass."
        lines = []
        for i, f in enumerate(failures[:20], 1):
            lines.append(
                f"{i}. [{f.get('layer')}] {f.get('failure_type')} "
                f"(Line {f.get('line_number') or 'N/A'}, "
                f"Cause: {f.get('cause') or 'N/A'}) "
                f"— Spec: {f.get('spec_reference') or 'N/A'}"
            )
        if len(failures) > 20:
            lines.append(f"  ... and {len(failures) - 20} more failures")
        return "\n".join(lines)

    def _format_chain(self, chain_data: Dict) -> str:
        if not chain_data or not chain_data.get("chains"):
            return "No cascading failure chains detected."
        lines = [
            f"Root Layer: {chain_data.get('root_layer', 'Unknown')}",
            f"Affected Layers: {', '.join(chain_data.get('affected_layers', []))}",
        ]
        for c in chain_data.get("chains", []):
            lines.append(f"  • {c.get('chain')}: {c.get('description')}")
            lines.append(f"    Likely Root: {c.get('likely_root')}")
        return "\n".join(lines)


# ── Singleton ──────────────────────────────────────────────────────────────────

_llm_service: Optional[GroqLLMService] = None


def get_llm_service() -> GroqLLMService:
    global _llm_service
    if _llm_service is None:
        _llm_service = GroqLLMService()
    return _llm_service
