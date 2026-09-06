"""
MCP Tool Registry
Implements the Model Context Protocol (MCP) pattern as a tool registry.
Tools are registered functions that can be called by name with parameters.
This is NOT an agentic AI system — tools are invoked directly by the LLM pipeline.
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# MCP Tool Schema
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MCPTool:
    """Represents a registered MCP tool."""
    name: str
    description: str
    parameters: Dict       # JSON-schema style parameter spec
    handler: Callable
    category: str = "general"


@dataclass
class MCPToolCall:
    """An invocation request for an MCP tool."""
    tool_name: str
    parameters: Dict = field(default_factory=dict)


@dataclass
class MCPToolResult:
    """Result from an MCP tool execution."""
    tool_name: str
    success: bool
    data: Any = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
        }


# ──────────────────────────────────────────────────────────────────────────────
# MCP Registry
# ──────────────────────────────────────────────────────────────────────────────

class MCPRegistry:
    """
    Registry of MCP tools for 3GPP log analysis.
    Tools are registered at startup and called by name during analysis.
    """

    def __init__(self):
        self._tools: Dict[str, MCPTool] = {}

    def register(self, name: str, description: str, parameters: Dict,
                 category: str = "general"):
        """Decorator factory to register a function as an MCP tool."""
        def decorator(fn: Callable) -> Callable:
            self._tools[name] = MCPTool(
                name=name,
                description=description,
                parameters=parameters,
                handler=fn,
                category=category,
            )
            logger.debug(f"MCP tool registered: {name}")
            return fn
        return decorator

    def call(self, tool_name: str, parameters: Dict = None) -> MCPToolResult:
        """Execute a registered tool by name."""
        parameters = parameters or {}
        if tool_name not in self._tools:
            return MCPToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' not found in MCP registry",
            )
        tool = self._tools[tool_name]
        try:
            result = tool.handler(**parameters)
            return MCPToolResult(tool_name=tool_name, success=True, data=result)
        except Exception as exc:
            logger.exception(f"MCP tool '{tool_name}' raised an exception")
            return MCPToolResult(tool_name=tool_name, success=False, error=str(exc))

    def call_batch(self, calls: List[MCPToolCall]) -> List[MCPToolResult]:
        """Execute multiple tool calls in sequence."""
        return [self.call(c.tool_name, c.parameters) for c in calls]

    def list_tools(self) -> List[Dict]:
        """Return all registered tools as a serializable list."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
                "category": t.category,
            }
            for t in self._tools.values()
        ]

    def get_tool_descriptions_for_prompt(self) -> str:
        """Return a compact string listing tools for use in LLM prompts."""
        lines = ["Available MCP Analysis Tools:"]
        for t in self._tools.values():
            lines.append(f"  - {t.name}: {t.description}")
        return "\n".join(lines)

    def __contains__(self, name: str) -> bool:
        return name in self._tools


# ──────────────────────────────────────────────────────────────────────────────
# Global Registry Instance
# ──────────────────────────────────────────────────────────────────────────────

registry = MCPRegistry()


# ──────────────────────────────────────────────────────────────────────────────
# Built-in Analysis Tools
# ──────────────────────────────────────────────────────────────────────────────

@registry.register(
    name="parse_logs",
    description="Parse raw 3GPP log text and extract events and failure points",
    parameters={
        "log_text": {"type": "string", "description": "Raw log content to parse"},
    },
    category="parsing",
)
def tool_parse_logs(log_text: str) -> Dict:
    from app.parsers.log_parser import parse_logs, failures_to_dict
    result = parse_logs(log_text)
    return {
        "summary": result.summary,
        "failures": failures_to_dict(result),
        "layers_found": result.layers_found,
    }


@registry.register(
    name="get_failure_summary",
    description="Return a structured summary of failure points from a parse result",
    parameters={
        "failures": {"type": "array", "description": "List of failure dicts from parse_logs"},
    },
    category="analysis",
)
def tool_get_failure_summary(failures: List[Dict]) -> Dict:
    if not failures:
        return {"total": 0, "by_layer": {}, "by_type": {}, "critical_failures": []}

    by_layer: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    critical: List[Dict] = []

    for f in failures:
        layer = f.get("layer", "UNKNOWN")
        ftype = f.get("failure_type", "Unknown")
        by_layer[layer] = by_layer.get(layer, 0) + 1
        by_type[ftype] = by_type.get(ftype, 0) + 1
        if f.get("severity") in ("CRITICAL", "ERROR"):
            critical.append({
                "line": f.get("line_number"),
                "type": ftype,
                "layer": layer,
                "cause": f.get("cause"),
                "spec": f.get("spec_reference"),
            })

    return {
        "total": len(failures),
        "by_layer": by_layer,
        "by_type": by_type,
        "critical_failures": critical[:10],  # top 10
    }


@registry.register(
    name="query_3gpp_spec",
    description="Search the 3GPP specification knowledge base for relevant information",
    parameters={
        "query": {"type": "string", "description": "Search query about 3GPP specs"},
        "n_results": {"type": "integer", "description": "Number of results to return", "default": 4},
    },
    category="rag",
)
def tool_query_3gpp_spec(query: str, n_results: int = 4) -> List[Dict]:
    from app.rag.vector_store import get_vector_store
    store = get_vector_store()
    return store.query(query, n_results=n_results)


@registry.register(
    name="detect_failure_chain",
    description="Detect cascading failure chains across protocol layers",
    parameters={
        "failures": {"type": "array", "description": "List of failure dicts"},
    },
    category="analysis",
)
def tool_detect_failure_chain(failures: List[Dict]) -> Dict:
    """Detect common failure cascade patterns."""
    if not failures:
        return {"chains": [], "root_layer": None}

    layer_order = ["MAC", "RLC", "PDCP", "RRC", "NAS", "NGAP", "S1AP", "GTP"]
    layers_with_failures = set(f.get("layer") for f in failures)

    chains = []

    # Pattern 1: RACH → RRC → NAS
    if "MAC" in layers_with_failures and "RRC" in layers_with_failures:
        chains.append({
            "chain": "MAC (RACH) → RRC Setup Failure",
            "description": "Random access failure led to RRC connection failure",
            "3gpp_ref": "TS 38.321 + TS 38.331",
            "likely_root": "Coverage gap or PRACH congestion",
        })

    # Pattern 2: RLC max retx → RLF → Re-establishment
    if "RLC" in layers_with_failures and "RRC" in layers_with_failures:
        chains.append({
            "chain": "RLC maxRetxThreshold → Radio Link Failure → RRC Re-establishment",
            "description": "RLC retransmission exhaustion triggered RLF and re-establishment attempt",
            "3gpp_ref": "TS 38.322 + TS 38.331",
            "likely_root": "Poor radio conditions (SINR degradation)",
        })

    # Pattern 3: RRC HO fail → NAS re-registration
    if "RRC" in layers_with_failures and "NAS" in layers_with_failures:
        chains.append({
            "chain": "RRC Handover Failure → NAS Re-registration",
            "description": "Failed handover forced UE to re-register via NAS",
            "3gpp_ref": "TS 38.331 + TS 24.501",
            "likely_root": "Handover configuration or target cell issue",
        })

    # Pattern 4: PDCP integrity → key mismatch → RRC release
    if "PDCP" in layers_with_failures:
        chains.append({
            "chain": "PDCP Integrity Failure → Security Key Mismatch → RRC Release",
            "description": "Security context corrupted, likely after handover",
            "3gpp_ref": "TS 38.323 + TS 38.331",
            "likely_root": "Key derivation failure post-handover",
        })

    # Determine root layer (lowest protocol layer with failures)
    root_layer = None
    for layer in layer_order:
        if layer in layers_with_failures:
            root_layer = layer
            break

    return {
        "chains": chains,
        "root_layer": root_layer,
        "affected_layers": sorted(layers_with_failures),
    }


@registry.register(
    name="get_3gpp_timer_info",
    description="Look up 3GPP timer information and recommended values",
    parameters={
        "timer_name": {"type": "string", "description": "Timer name e.g. T310, T304, T300"},
    },
    category="reference",
)
def tool_get_3gpp_timer_info(timer_name: str) -> Dict:
    timer_db = {
        "T300": {"spec": "TS 38.331", "default": "1000ms", "purpose": "RRCSetupRequest timeout",
                 "on_expiry": "RRC connection attempt failure, PLMN selection"},
        "T301": {"spec": "TS 38.331", "default": "1000ms", "purpose": "RRCReestablishmentRequest timeout",
                 "on_expiry": "Move to RRC_IDLE, re-initiate RRC connection"},
        "T302": {"spec": "TS 38.331", "default": "per RRCReject waitTime",
                 "purpose": "RRCReject back-off", "on_expiry": "Retry RRC connection"},
        "T304": {"spec": "TS 38.331", "default": "50-2000ms (configured by gNB)",
                 "purpose": "Handover execution timer",
                 "on_expiry": "Declare handover failure, attempt re-establishment (cause=handoverFailure)"},
        "T310": {"spec": "TS 38.331", "default": "1000ms",
                 "purpose": "Started after N310 out-of-sync indications",
                 "on_expiry": "Declare Radio Link Failure"},
        "T311": {"spec": "TS 38.331", "default": "1000ms",
                 "purpose": "RRC re-establishment PLMN/cell search",
                 "on_expiry": "Move to RRC_IDLE if no suitable cell found"},
        "T3510": {"spec": "TS 24.501", "default": "15s",
                  "purpose": "Registration Request retransmission",
                  "on_expiry": "Retry registration, increment attempt counter"},
        "T3512": {"spec": "TS 24.501", "default": "54 minutes",
                  "purpose": "Periodic registration timer",
                  "on_expiry": "Initiate periodic registration update"},
        "T3346": {"spec": "TS 24.501", "default": "network-assigned",
                  "purpose": "Congestion back-off timer",
                  "on_expiry": "Retry registration request"},
        "T3396": {"spec": "TS 24.501", "default": "network-assigned",
                  "purpose": "PDU session back-off timer",
                  "on_expiry": "Retry PDU session establishment"},
    }
    key = timer_name.upper().strip()
    if key in timer_db:
        return {"timer": key, **timer_db[key]}
    # fuzzy match
    for t_name, t_info in timer_db.items():
        if key in t_name or t_name in key:
            return {"timer": t_name, **t_info}
    return {"timer": timer_name, "error": "Timer not found in reference database"}


@registry.register(
    name="get_cause_code_explanation",
    description="Explain a 3GPP NAS or RRC cause code",
    parameters={
        "layer": {"type": "string", "description": "Protocol layer: NAS, RRC, NGAP, S1AP"},
        "cause": {"type": "string", "description": "Cause code or name"},
    },
    category="reference",
)
def tool_get_cause_code_explanation(layer: str, cause: str) -> Dict:
    nas_causes = {
        "#3": "Illegal UE — USIM blocked or invalid",
        "#6": "Illegal ME — IMEI barred by network",
        "#7": "5GS services not allowed — subscription does not include 5G",
        "#11": "PLMN not allowed — SIM not provisioned for this PLMN",
        "#12": "Tracking area not allowed — TA not in subscription",
        "#13": "Roaming not allowed in tracking area",
        "#15": "No suitable cells in tracking area — coverage issue",
        "#22": "Congestion — T3346 back-off timer active",
        "#27": "Unknown DNN — DNN not configured on SMF/PGW",
        "#29": "User authentication or authorization failed",
        "#38": "Network failure — SMF/UPF internal error",
    }
    rrc_causes = {
        "t300-Expiry": "RRCSetupRequest timed out — gNB did not respond",
        "t301-Expiry": "Re-establishment response not received",
        "t304-Expiry": "Handover execution failed — UE could not sync to target",
        "radioLinkFailure": "Physical layer RLF — T310 expired after N310 out-of-sync",
        "handoverFailure": "Handover procedure failed",
        "otherFailure": "Unspecified failure — check combined logs",
        "reconfigurationFailure": "RRC Reconfiguration rejected by UE",
    }

    cause_str = str(cause).strip()
    if layer.upper() in ("NAS", "5GMM", "EMM"):
        for key, val in nas_causes.items():
            if key in cause_str or cause_str in key:
                return {"layer": "NAS", "cause": key, "explanation": val,
                        "spec": "TS 24.501 / TS 24.301"}
    elif layer.upper() == "RRC":
        for key, val in rrc_causes.items():
            if key.lower() in cause_str.lower() or cause_str.lower() in key.lower():
                return {"layer": "RRC", "cause": key, "explanation": val,
                        "spec": "TS 38.331"}

    return {"layer": layer, "cause": cause, "explanation": "Not found in quick reference",
            "suggestion": "Query 3GPP spec knowledge base for more details"}
