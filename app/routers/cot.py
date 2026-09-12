"""
CoT (Chain-of-Thought) Template Router
CRUD endpoints for managing and selecting CoT templates.
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cot", tags=["cot"])


# ── Request / Response models ─────────────────────────────────────────────────

class AnalysisStepIn(BaseModel):
    step: int
    title: str
    instruction: str
    spec_ref: str = ""
    what_to_look_for: List[str] = []


class CoTCreateRequest(BaseModel):
    name: str
    issue_type: str = "Custom"
    description: str = ""
    tags: List[str] = []
    call_flow: List[str] = []
    analysis_steps: List[AnalysisStepIn] = []
    expected_failure_sequence: List[str] = []


class CoTUpdateRequest(BaseModel):
    name: Optional[str] = None
    issue_type: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    call_flow: Optional[List[str]] = None
    analysis_steps: Optional[List[AnalysisStepIn]] = None
    expected_failure_sequence: Optional[List[str]] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/templates")
def list_templates():
    """List all available CoT templates (built-in + user-defined)."""
    from app.cot.template_manager import get_template_manager
    return {"templates": get_template_manager().list_all()}


@router.get("/templates/{template_id}")
def get_template(template_id: str):
    """Get full CoT template by ID."""
    from app.cot.template_manager import get_template_manager
    tmpl = get_template_manager().get(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return tmpl


@router.post("/templates")
def create_template(body: CoTCreateRequest):
    """Create a new user-defined CoT template."""
    from app.cot.template_manager import get_template_manager
    data = body.model_dump()
    # Convert AnalysisStepIn objects to plain dicts
    data["analysis_steps"] = [s.model_dump() for s in body.analysis_steps]
    created = get_template_manager().create(data)
    return {"message": "Template created", "template": created}


@router.put("/templates/{template_id}")
def update_template(template_id: str, body: CoTUpdateRequest):
    """Update a user-defined template (built-ins are read-only)."""
    from app.cot.template_manager import get_template_manager
    mgr  = get_template_manager()
    tmpl = mgr.get(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    if tmpl.get("is_builtin"):
        raise HTTPException(status_code=403, detail="Built-in templates cannot be modified")
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    if "analysis_steps" in data and data["analysis_steps"]:
        data["analysis_steps"] = [
            s.model_dump() if hasattr(s, "model_dump") else s
            for s in data["analysis_steps"]
        ]
    updated = mgr.update(template_id, data)
    if not updated:
        raise HTTPException(status_code=500, detail="Update failed")
    return {"message": "Template updated", "template": updated}


@router.delete("/templates/{template_id}")
def delete_template(template_id: str):
    """Delete a user-defined template."""
    from app.cot.template_manager import get_template_manager
    mgr  = get_template_manager()
    tmpl = mgr.get(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    if tmpl.get("is_builtin"):
        raise HTTPException(status_code=403, detail="Built-in templates cannot be deleted")
    mgr.delete(template_id)
    return {"message": f"Template '{template_id}' deleted"}


@router.get("/templates/{template_id}/preview")
def preview_template_prompt(template_id: str):
    """Preview the formatted CoT prompt block that will be injected into the LLM."""
    from app.cot.template_manager import get_template_manager
    mgr  = get_template_manager()
    tmpl = mgr.get(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return {"prompt_block": mgr.format_for_prompt(tmpl)}
