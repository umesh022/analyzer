"""
CoT Template Manager
Manages Chain-of-Thought analysis templates.
Built-in templates live in cot_templates/builtin_templates.json.
User-created templates are stored in cot_templates/user_templates.json.
"""

import os
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Resolve paths relative to project root
_BASE_DIR     = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_COT_DIR      = os.path.join(_BASE_DIR, "cot_templates")
_BUILTIN_FILE = os.path.join(_COT_DIR, "builtin_templates.json")
_USER_FILE    = os.path.join(_COT_DIR, "user_templates.json")


class CoTTemplateManager:
    """Load, list, create, update and delete CoT templates."""

    def __init__(self):
        os.makedirs(_COT_DIR, exist_ok=True)
        self._builtin: List[Dict] = self._load_file(_BUILTIN_FILE)
        self._user:    List[Dict] = self._load_file(_USER_FILE)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_file(self, path: str) -> List[Dict]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"CoT load error {path}: {e}")
            return []

    def _save_user(self):
        try:
            with open(_USER_FILE, "w", encoding="utf-8") as f:
                json.dump(self._user, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"CoT save error: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def list_all(self) -> List[Dict]:
        """Return all templates (built-in + user), summary fields only."""
        result = []
        for t in self._builtin + self._user:
            result.append({
                "id":          t["id"],
                "name":        t["name"],
                "issue_type":  t["issue_type"],
                "description": t["description"],
                "tags":        t.get("tags", []),
                "is_builtin":  t.get("is_builtin", False),
                "steps_count": len(t.get("analysis_steps", [])),
            })
        return result

    def get(self, template_id: str) -> Optional[Dict]:
        """Return full template by ID."""
        for t in self._builtin + self._user:
            if t["id"] == template_id:
                return t
        return None

    def create(self, data: Dict) -> Dict:
        """Create a new user-defined template. Returns the created template."""
        new_template = {
            "id":          data.get("id") or str(uuid.uuid4())[:8],
            "name":        data["name"],
            "issue_type":  data.get("issue_type", "Custom"),
            "description": data.get("description", ""),
            "tags":        data.get("tags", []),
            "call_flow":   data.get("call_flow", []),
            "analysis_steps": data.get("analysis_steps", []),
            "expected_failure_sequence": data.get("expected_failure_sequence", []),
            "is_builtin":  False,
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }
        # Ensure unique ID
        existing_ids = {t["id"] for t in self._builtin + self._user}
        while new_template["id"] in existing_ids:
            new_template["id"] = str(uuid.uuid4())[:8]

        self._user.append(new_template)
        self._save_user()
        logger.info(f"CoT template created: {new_template['id']} — {new_template['name']}")
        return new_template

    def update(self, template_id: str, data: Dict) -> Optional[Dict]:
        """Update a user-defined template (built-ins cannot be modified)."""
        for i, t in enumerate(self._user):
            if t["id"] == template_id:
                for key in ["name", "issue_type", "description", "tags",
                            "call_flow", "analysis_steps",
                            "expected_failure_sequence"]:
                    if key in data:
                        self._user[i][key] = data[key]
                self._user[i]["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._save_user()
                return self._user[i]
        return None  # not found or is builtin

    def delete(self, template_id: str) -> bool:
        """Delete a user-defined template. Returns True if deleted."""
        before = len(self._user)
        self._user = [t for t in self._user if t["id"] != template_id]
        if len(self._user) < before:
            self._save_user()
            return True
        return False

    def format_for_prompt(self, template: Dict) -> str:
        """
        Format a CoT template as a structured prompt block to be injected
        into the Groq LLM RCA prompt.
        """
        lines = [
            f"═══ CHAIN-OF-THOUGHT ANALYSIS TEMPLATE ═══",
            f"Issue Type : {template['issue_type']}",
            f"Template   : {template['name']}",
            f"",
            f"STANDARD CALL FLOW ({template['issue_type']}):",
        ]
        for i, step in enumerate(template.get("call_flow", []), 1):
            lines.append(f"  {i}. {step}")

        lines.append("")
        lines.append("ANALYSIS STEPS — follow these in order:")
        for step in template.get("analysis_steps", []):
            lines.append(f"")
            lines.append(f"  STEP {step['step']}: {step['title']}")
            lines.append(f"  Spec: {step['spec_ref']}")
            lines.append(f"  Instructions: {step['instruction']}")
            lines.append(f"  Look for: {', '.join(step.get('what_to_look_for', []))}")

        if template.get("expected_failure_sequence"):
            lines.append("")
            lines.append("EXPECTED FAILURE SEQUENCE:")
            for item in template["expected_failure_sequence"]:
                lines.append(f"  → {item}")

        lines.append("")
        lines.append(
            "IMPORTANT: Follow the above steps sequentially in your RCA. "
            "For each step, cite findings from the log and reference the 3GPP spec. "
            "If a step's evidence is absent from the log, state that explicitly."
        )
        lines.append("═══════════════════════════════════════════")
        return "\n".join(lines)


# ── Singleton ─────────────────────────────────────────────────────────────────

_manager: Optional[CoTTemplateManager] = None


def get_template_manager() -> CoTTemplateManager:
    global _manager
    if _manager is None:
        _manager = CoTTemplateManager()
    return _manager
