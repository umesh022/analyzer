"""
Analysis Pipeline
Orchestrates: Log Parsing → MCP Tools → RAG Retrieval → Groq LLM RCA
This is a straightforward pipeline, NOT an agentic AI system.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """
    End-to-end 3GPP log analysis pipeline.
    Steps:
      1. Parse logs with LogParser
      2. Run MCP tools: failure summary + chain detection
      3. Build RAG context from VectorStore
      4. Generate RCA with Groq LLM
    """

    def __init__(self):
        from app.parsers.log_parser import parse_logs, failures_to_dict
        from app.mcp.tool_registry import registry
        from app.rag.vector_store import get_vector_store
        from app.services.groq_llm import get_llm_service

        self._parse_logs = parse_logs
        self._failures_to_dict = failures_to_dict
        self._registry = registry
        self._get_vector_store = get_vector_store
        self._get_llm = get_llm_service

    def run(self, log_text: str) -> Dict:
        """
        Execute the full analysis pipeline synchronously.
        Returns a complete analysis result dict.
        """
        logger.info("Starting analysis pipeline")

        # ── Step 1: Parse Logs ────────────────────────────────────────────────
        parse_result = self._parse_logs(log_text)
        failures = self._failures_to_dict(parse_result)
        logger.info(f"Parsed {parse_result.total_lines} lines, "
                    f"found {len(failures)} failures")

        # ── Step 2: MCP Tools ─────────────────────────────────────────────────
        # 2a: Failure summary
        summary_result = self._registry.call("get_failure_summary", {"failures": failures})
        failure_summary = summary_result.data if summary_result.success else {}

        # 2b: Failure chain detection
        chain_result = self._registry.call("detect_failure_chain", {"failures": failures})
        chain_analysis = chain_result.data if chain_result.success else {}

        logger.info(f"MCP chain analysis: root_layer={chain_analysis.get('root_layer')}")

        # ── Step 3: RAG Context ───────────────────────────────────────────────
        rag_context = ""
        try:
            store = self._get_vector_store()
            if store.is_populated():
                rag_context = store.build_context(failures, top_k=5)
                logger.info("RAG context built successfully")
            else:
                logger.warning("Vector store not populated — skipping RAG")
        except Exception as e:
            logger.error(f"RAG context build failed: {e}")

        # ── Step 4: Groq LLM RCA ──────────────────────────────────────────────
        llm = self._get_llm()
        rca_report = llm.generate_rca(
            failures=failures,
            rag_context=rag_context,
            mcp_chain_analysis=chain_analysis,
            log_snippet=log_text,
        )
        logger.info("RCA generation complete")

        return {
            "parse_summary": parse_result.summary,
            "failures": failures,
            "failure_summary": failure_summary,
            "chain_analysis": chain_analysis,
            "rag_context_used": bool(rag_context),
            "rca_report": rca_report,
            "layers_found": parse_result.layers_found,
            "total_lines": parse_result.total_lines,
        }

    def get_quick_summary(self, log_text: str) -> Dict:
        """
        Quick parse-only summary (no LLM call) — useful for initial display.
        """
        parse_result = self._parse_logs(log_text)
        failures = self._failures_to_dict(parse_result)

        summary_result = self._registry.call("get_failure_summary", {"failures": failures})
        chain_result = self._registry.call("detect_failure_chain", {"failures": failures})

        return {
            "parse_summary": parse_result.summary,
            "failures": failures[:20],  # first 20 only
            "failure_summary": summary_result.data if summary_result.success else {},
            "chain_analysis": chain_result.data if chain_result.success else {},
            "layers_found": parse_result.layers_found,
        }


# Singleton
_pipeline: Optional[AnalysisPipeline] = None


def get_pipeline() -> AnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline
