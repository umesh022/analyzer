"""
Groq LLM Service
Model: qwen/qwen3.6-27b hosted on GroqCloud LPU infrastructure.
Thinking mode is disabled — responses are direct answers only.
Used for RCA generation and chat — no agentic loops.
"""

import re
import os
import logging
from typing import List, Dict, Optional, AsyncGenerator

from groq import Groq, AsyncGroq

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "groq/compound-mini"

# Qwen3 thinking-mode is suppressed via /no_thinking in system prompt
# Strip any <think>…</think> blocks that still leak through
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

def _strip_thinking(text: str) -> str:
    """Remove Qwen3 chain-of-thought blocks from a completed response."""
    return _THINK_RE.sub("", text).strip()


# ── System Prompts ────────────────────────────────────────────────────────────

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

CHAT_SYSTEM_PROMPT = """You are a log analysis assistant. Your job is to answer questions about the specific log that was uploaded and analyzed in this session.

You have access to:
1. The parsed failure points (layer, cause, spec reference, line number)
2. The failure chain analysis and RCA report
3. The FULL RAW LOG TEXT — read this carefully to answer any question about log content

RULES:
- Answer ONLY from the log data provided in the context below. Do not invent or assume anything not present.
- If the question asks about something in the raw log (e.g. IMSI, IP address, timestamp, parameter value), read the raw log text and extract the exact value. Quote the relevant log line.
- If a value is not present anywhere in the log, say exactly: "This information is not present in the uploaded log."
- Always cite the line number or log line when giving a specific answer.
- Do not answer questions completely unrelated to the uploaded log (e.g. cooking, general knowledge).
- Keep answers concise and factual. No padding."""


# ── Service ───────────────────────────────────────────────────────────────────

class GroqLLMService:
    """
    Groq-hosted LLM client (qwen/qwen3.6-27b).

    Environment variables:
      GROQ_API_KEY  — required, obtain at https://console.groq.com
      GROQ_MODEL    — model ID on Groq (default: qwen/qwen3.6-27b)
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

    # ── Client factories ──────────────────────────────────────────────────────

    def _get_client(self) -> Groq:
        if self._client is None:
            self._client = Groq(api_key=self.api_key)
        return self._client

    def _get_async_client(self) -> AsyncGroq:
        if self._async_client is None:
            self._async_client = AsyncGroq(api_key=self.api_key)
        return self._async_client

    # ── RCA Generation (sync) ─────────────────────────────────────────────────

    def generate_rca(self, failures: List[Dict], rag_context: str,
                     mcp_chain_analysis: Dict, log_snippet: str = "") -> str:
        """Generate a full Root Cause Analysis report."""
        if not self.api_key:
            return "⚠️ GROQ_API_KEY not configured. Please set it in your .env file."

        failure_summary = self._format_failures(failures)
        chain_text      = self._format_chain(mcp_chain_analysis)

        prompt = f"""## Log Analysis Request

### Detected Failures
{failure_summary}

### Failure Chain Analysis
{chain_text}

### Relevant 3GPP Specification Context (RAG)
{rag_context if rag_context else "No RAG context available."}

### Log Snippet (first 2000 chars)
```
{log_snippet[:2000]}
```

## Task
Provide a comprehensive Root Cause Analysis (RCA) structured as:
1. **Executive Summary** — What failed and when
2. **Failure Point Analysis** — Each failure with its 3GPP spec reference
3. **Root Cause** — Primary root cause with technical evidence
4. **Cascading Impact** — How failures propagated across protocol layers
5. **Recommended Corrective Actions** — Specific, actionable fixes with config examples
6. **Preventive Measures** — How to prevent recurrence
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

    # ── Chat (async, single-shot) ─────────────────────────────────────────────

    async def chat(self, messages: List[Dict], rag_context: str = "",
                   analysis_context: str = "") -> str:
        """Async single-shot chat with optional RAG and analysis context."""
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

    # ── Streaming Chat (async) ────────────────────────────────────────────────

    async def stream_chat(self, messages: List[Dict], rag_context: str = "",
                          analysis_context: str = "") -> AsyncGenerator[str, None]:
        """Async token-by-token streaming — skips <think> blocks."""
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

            # Buffer to absorb any partial <think> tag that spans chunks
            buffer = ""
            in_think = False

            async for chunk in stream:
                delta = chunk.choices[0].delta.content
                if not delta:
                    continue

                buffer += delta

                # Drain buffer — suppress everything inside <think>...</think>
                while True:
                    if in_think:
                        end = buffer.find("</think>")
                        if end == -1:
                            # Still inside thinking block — consume buffer, wait
                            buffer = ""
                            break
                        else:
                            # Found end of thinking block — discard up to </think>
                            buffer = buffer[end + len("</think>"):]
                            in_think = False
                    else:
                        start = buffer.find("<think>")
                        if start == -1:
                            # No thinking tag — yield all buffered content
                            if buffer:
                                yield buffer
                                buffer = ""
                            break
                        else:
                            # Yield content before the thinking block
                            if start > 0:
                                yield buffer[:start]
                            buffer = buffer[start + len("<think>"):]
                            in_think = True

            # Flush anything remaining
            if buffer and not in_think:
                yield buffer

        except Exception as e:
            logger.error(f"Groq stream_chat failed: {e}")
            yield f"❌ LLM Streaming Error: {str(e)}"

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_messages(self, messages: List[Dict],
                        rag_context: str, analysis_context: str) -> List[Dict]:
        system = CHAT_SYSTEM_PROMPT
        if rag_context:
            system += f"\n\n{rag_context}"
        if analysis_context:
            system += f"\n\n### Current Analysis Context\n{analysis_context}"
        return [{"role": "system", "content": system}] + messages

    def _format_failures(self, failures: List[Dict]) -> str:
        if not failures:
            return "No failures detected."
        lines = []
        for i, f in enumerate(failures[:15], 1):
            lines.append(
                f"{i}. [{f.get('layer')}] {f.get('failure_type')} "
                f"(Line {f.get('line_number')}, Cause: {f.get('cause', 'N/A')}) "
                f"— Spec: {f.get('spec_reference', 'N/A')}"
            )
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


# ── Singleton ─────────────────────────────────────────────────────────────────

_llm_service: Optional[GroqLLMService] = None


def get_llm_service() -> GroqLLMService:
    global _llm_service
    if _llm_service is None:
        _llm_service = GroqLLMService()
    return _llm_service
