"""
Analysis Pipeline
Orchestrates: Log Parsing → LLM Pre-pass (if 0 regex hits) →
              MCP Tools → RAG Retrieval → Groq LLM RCA

NOT an agentic AI system — every step is a direct, sequential function call.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """
    End-to-end 3GPP log analysis pipeline.

    Steps:
      1.  Parse logs with LogParser (regex-based, 30 broad multi-vendor patterns)
      1.5 LLM pre-pass: if regex found 0 failures, ask the LLM to extract them
          directly from the raw log as structured JSON (Task 2 fix)
      2.  MCP tools: failure summary + chain detection
      3.  RAG: retrieve relevant 3GPP spec chunks
      4.  Groq LLM: generate full RCA report (log snippet now 8000 chars)
    """

    def __init__(self):
        from app.parsers.log_parser import parse_logs, failures_to_dict
        from app.mcp.tool_registry import registry
        from app.rag.vector_store import get_vector_store
        from app.services.groq_llm import get_llm_service

        self._parse_logs        = parse_logs
        self._failures_to_dict  = failures_to_dict
        self._registry          = registry
        self._get_vector_store  = get_vector_store
        self._get_llm           = get_llm_service

    # ── Full pipeline (with LLM RCA) ──────────────────────────────────────────

    def run(self, log_text: str) -> Dict:
        logger.info("=== Analysis pipeline START ===")

        # ── Step 1: Regex parsing ─────────────────────────────────────────────
        parse_result = self._parse_logs(log_text)
        failures     = self._failures_to_dict(parse_result)
        logger.info(f"Regex parser: {parse_result.total_lines} lines, "
                    f"{len(failures)} failures detected")

        llm_prepass_used = False

        # ── Step 1.5: LLM pre-pass when regex finds nothing ───────────────────
        if not failures:
            logger.info("Regex found 0 failures — running LLM pre-pass extraction")
            try:
                llm           = self._get_llm()
                llm_failures  = llm.extract_failures_from_log(log_text)
                if llm_failures:
                    failures         = llm_failures
                    llm_prepass_used = True
                    # Update summary to reflect LLM-found failures
                    parse_result.summary["total_failures"]   = len(failures)
                    parse_result.summary["llm_prepass_used"] = True
                    logger.info(f"LLM pre-pass found {len(failures)} failures")
                else:
                    logger.info("LLM pre-pass also found no failures — log may be clean")
                    parse_result.summary["llm_prepass_used"] = True
            except Exception as e:
                logger.error(f"LLM pre-pass error: {e}")
        else:
            parse_result.summary["llm_prepass_used"] = False

        # ── Step 2: MCP tools ─────────────────────────────────────────────────
        summary_result  = self._registry.call("get_failure_summary", {"failures": failures})
        failure_summary = summary_result.data if summary_result.success else {}

        chain_result   = self._registry.call("detect_failure_chain", {"failures": failures})
        chain_analysis = chain_result.data if chain_result.success else {}

        logger.info(f"MCP: root_layer={chain_analysis.get('root_layer')}, "
                    f"chains={len(chain_analysis.get('chains', []))}")

        # ── Step 3: RAG context ───────────────────────────────────────────────
        rag_context = ""
        try:
            store = self._get_vector_store()
            if store.is_populated():
                rag_context = store.build_context(failures, top_k=5)
                logger.info("RAG context built")
            else:
                logger.warning("Vector store empty — skipping RAG")
        except Exception as e:
            logger.error(f"RAG build failed: {e}")

        # ── Step 4: Groq LLM RCA ──────────────────────────────────────────────
        llm        = self._get_llm()
        rca_report = llm.generate_rca(
            failures          = failures,
            rag_context       = rag_context,
            mcp_chain_analysis= chain_analysis,
            log_snippet       = log_text,   # full text — sliced inside generate_rca
        )
        logger.info("=== Analysis pipeline DONE ===")

        return {
            "parse_summary":    parse_result.summary,
            "failures":         failures,
            "failure_summary":  failure_summary,
            "chain_analysis":   chain_analysis,
            "rag_context_used": bool(rag_context),
            "llm_prepass_used": llm_prepass_used,
            "rca_report":       rca_report,
            "layers_found":     parse_result.layers_found,
            "total_lines":      parse_result.total_lines,
        }

    # ── Quick parse (no LLM RCA, but still runs pre-pass for failure count) ───

    def get_quick_summary(self, log_text: str) -> Dict:
        """Fast parse without RCA generation. Runs pre-pass if regex misses."""
        parse_result = self._parse_logs(log_text)
        failures     = self._failures_to_dict(parse_result)
        llm_prepass_used = False

        if not failures:
            try:
                llm          = self._get_llm()
                llm_failures = llm.extract_failures_from_log(log_text)
                if llm_failures:
                    failures         = llm_failures
                    llm_prepass_used = True
                    parse_result.summary["total_failures"]   = len(failures)
                    parse_result.summary["llm_prepass_used"] = True
            except Exception as e:
                logger.error(f"Quick-summary LLM pre-pass error: {e}")

        summary_result = self._registry.call("get_failure_summary", {"failures": failures})
        chain_result   = self._registry.call("detect_failure_chain", {"failures": failures})

        return {
            "parse_summary":    parse_result.summary,
            "failures":         failures[:20],
            "failure_summary":  summary_result.data if summary_result.success else {},
            "chain_analysis":   chain_result.data  if chain_result.success  else {},
            "llm_prepass_used": llm_prepass_used,
            "layers_found":     parse_result.layers_found,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_pipeline: Optional[AnalysisPipeline] = None


def get_pipeline() -> AnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline
