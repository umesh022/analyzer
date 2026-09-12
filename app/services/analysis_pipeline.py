"""
Analysis Pipeline
Orchestrates: Log Parsing → LLM Pre-pass (if 0 regex hits) →
              MCP Tools → RAG Retrieval → CoT Injection → Groq LLM RCA

NOT an agentic AI system — every step is a direct, sequential function call.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """
    End-to-end 3GPP log analysis pipeline.

    Steps:
      1.   Parse logs (regex — 30 broad multi-vendor patterns)
      1.5  LLM pre-pass: if 0 regex hits, ask LLM to extract failures as JSON
      2.   MCP tools: failure summary + chain detection
      3.   RAG: retrieve relevant 3GPP spec chunks
      3.5  CoT injection: if a CoT template_id is supplied, format it into
           a structured prompt block that the LLM follows step-by-step
      4.   Groq LLM: generate full RCA following CoT steps (if provided)
    """

    def __init__(self):
        from app.parsers.log_parser import parse_logs, failures_to_dict
        from app.mcp.tool_registry import registry
        from app.rag.vector_store import get_vector_store
        from app.services.groq_llm import get_llm_service

        self._parse_logs       = parse_logs
        self._failures_to_dict = failures_to_dict
        self._registry         = registry
        self._get_vector_store = get_vector_store
        self._get_llm          = get_llm_service

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run(self, log_text: str, cot_template_id: Optional[str] = None) -> Dict:
        """
        Run the full pipeline.
        cot_template_id: optional CoT template to guide the RCA analysis.
        """
        logger.info(f"=== Analysis pipeline START (cot={cot_template_id}) ===")

        # ── Step 1: Regex parsing ─────────────────────────────────────────────
        parse_result = self._parse_logs(log_text)
        failures     = self._failures_to_dict(parse_result)
        logger.info(f"Regex: {parse_result.total_lines} lines, {len(failures)} failures")

        llm_prepass_used = False

        # ── Step 1.5: LLM pre-pass when regex finds nothing ───────────────────
        if not failures:
            logger.info("0 regex failures → running LLM pre-pass extraction")
            try:
                llm_failures = self._get_llm().extract_failures_from_log(log_text)
                if llm_failures:
                    failures         = llm_failures
                    llm_prepass_used = True
                    parse_result.summary["total_failures"]   = len(failures)
                    parse_result.summary["llm_prepass_used"] = True
                    logger.info(f"LLM pre-pass: {len(failures)} failures")
                else:
                    parse_result.summary["llm_prepass_used"] = True
            except Exception as e:
                logger.error(f"LLM pre-pass error: {e}")
        else:
            parse_result.summary["llm_prepass_used"] = False

        # ── Step 2: MCP tools ─────────────────────────────────────────────────
        summary_result = self._registry.call("get_failure_summary", {"failures": failures})
        failure_summary = summary_result.data if summary_result.success else {}

        chain_result   = self._registry.call("detect_failure_chain", {"failures": failures})
        chain_analysis = chain_result.data if chain_result.success else {}
        logger.info(f"MCP: root={chain_analysis.get('root_layer')}")

        # ── Step 3: RAG context ───────────────────────────────────────────────
        rag_context = ""
        try:
            store = self._get_vector_store()
            if store.is_populated():
                rag_context = store.build_context(failures, top_k=5)
                logger.info("RAG: context built")
            else:
                logger.warning("RAG: vector store empty")
        except Exception as e:
            logger.error(f"RAG error: {e}")

        # ── Step 3.5: CoT template injection ──────────────────────────────────
        cot_prompt_block = ""
        cot_template     = None
        if cot_template_id:
            try:
                from app.cot.template_manager import get_template_manager
                mgr  = get_template_manager()
                tmpl = mgr.get(cot_template_id)
                if tmpl:
                    cot_prompt_block = mgr.format_for_prompt(tmpl)
                    cot_template     = {
                        "id":         tmpl["id"],
                        "name":       tmpl["name"],
                        "issue_type": tmpl["issue_type"],
                    }
                    logger.info(f"CoT: injecting template '{tmpl['name']}'")
                else:
                    logger.warning(f"CoT template '{cot_template_id}' not found — skipping")
            except Exception as e:
                logger.error(f"CoT injection error: {e}")

        # ── Step 4: Groq LLM RCA ──────────────────────────────────────────────
        rca_report = self._get_llm().generate_rca(
            failures           = failures,
            rag_context        = rag_context,
            mcp_chain_analysis = chain_analysis,
            log_snippet        = log_text,
            cot_prompt_block   = cot_prompt_block,
        )
        logger.info("=== Analysis pipeline DONE ===")

        return {
            "parse_summary":    parse_result.summary,
            "failures":         failures,
            "failure_summary":  failure_summary,
            "chain_analysis":   chain_analysis,
            "rag_context_used": bool(rag_context),
            "llm_prepass_used": llm_prepass_used,
            "cot_template":     cot_template,
            "rca_report":       rca_report,
            "layers_found":     parse_result.layers_found,
            "total_lines":      parse_result.total_lines,
        }

    # ── Quick parse (no RCA, still runs pre-pass) ─────────────────────────────

    def get_quick_summary(self, log_text: str,
                          cot_template_id: Optional[str] = None) -> Dict:
        parse_result = self._parse_logs(log_text)
        failures     = self._failures_to_dict(parse_result)
        llm_prepass_used = False

        if not failures:
            try:
                llm_failures = self._get_llm().extract_failures_from_log(log_text)
                if llm_failures:
                    failures         = llm_failures
                    llm_prepass_used = True
                    parse_result.summary["total_failures"]   = len(failures)
                    parse_result.summary["llm_prepass_used"] = True
            except Exception as e:
                logger.error(f"Quick pre-pass error: {e}")

        summary_result = self._registry.call("get_failure_summary", {"failures": failures})
        chain_result   = self._registry.call("detect_failure_chain", {"failures": failures})

        # CoT name for display even in quick mode
        cot_template = None
        if cot_template_id:
            try:
                from app.cot.template_manager import get_template_manager
                tmpl = get_template_manager().get(cot_template_id)
                if tmpl:
                    cot_template = {"id": tmpl["id"], "name": tmpl["name"],
                                    "issue_type": tmpl["issue_type"]}
            except Exception:
                pass

        return {
            "parse_summary":    parse_result.summary,
            "failures":         failures[:20],
            "failure_summary":  summary_result.data if summary_result.success else {},
            "chain_analysis":   chain_result.data  if chain_result.success  else {},
            "llm_prepass_used": llm_prepass_used,
            "cot_template":     cot_template,
            "layers_found":     parse_result.layers_found,
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_pipeline: Optional[AnalysisPipeline] = None


def get_pipeline() -> AnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline
