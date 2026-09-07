"""Relational SQLite Repository for Incident Workflows in ULPF Phase 9."""

from __future__ import annotations

import json
from typing import Any

from ulpf_storage.database.relational import SQLiteDatabase

from ulpf_advanced_intelligence.models.workflows import (
    ActionApprovalState,
    IncidentPriority,
    IncidentTask,
    IncidentTaskStatus,
    IncidentWorkflow,
    SOARAction,
)


class IncidentRepository:
    """Durable relational persistence for incident response workflows."""

    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def save(self, incident: IncidentWorkflow) -> None:
        sql = """
        INSERT OR REPLACE INTO advanced_incidents (
            incident_id, title, priority, tenant_id, case_id, status,
            assignee, team, alert_ids_json, tasks_json, actions_json,
            sla_deadline, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            incident.incident_id,
            incident.title,
            incident.priority.value,
            incident.tenant_id,
            incident.case_id,
            incident.status,
            incident.assignee,
            incident.team,
            json.dumps(list(incident.alert_ids)),
            json.dumps([t.to_dict() for t in incident.tasks]),
            json.dumps([a.to_dict() for a in incident.actions]),
            incident.sla_deadline,
            incident.created_at,
            incident.updated_at,
        )
        self._db.execute(sql, params)

    def get(self, incident_id: str) -> IncidentWorkflow | None:
        sql = "SELECT * FROM advanced_incidents WHERE incident_id = ?"
        rows = self._db.execute(sql, (incident_id,))
        if not rows:
            return None
        return self._row_to_incident(rows[0])

    @staticmethod
    def _row_to_incident(row: dict[str, Any]) -> IncidentWorkflow:
        raw_tasks = json.loads(row["tasks_json"] or "[]")
        tasks = [
            IncidentTask(
                task_id=t["task_id"],
                title=t["title"],
                description=t["description"],
                status=IncidentTaskStatus(t["status"]),
                assignee=t.get("assignee"),
                created_at=t["created_at"],
                completed_at=t.get("completed_at"),
            )
            for t in raw_tasks
        ]

        raw_actions = json.loads(row["actions_json"] or "[]")
        actions = [
            SOARAction(
                action_id=a["action_id"],
                action_type=a["action_type"],
                target=a["target"],
                parameters=a.get("parameters", {}),
                approval_state=ActionApprovalState(a["approval_state"]),
                proposed_by=a.get("proposed_by", "SYSTEM"),
                approved_by=a.get("approved_by"),
                executed_at=a.get("executed_at"),
                result_summary=a.get("result_summary"),
                tenant_id=a.get("tenant_id"),
            )
            for a in raw_actions
        ]

        return IncidentWorkflow(
            incident_id=row["incident_id"],
            title=row["title"],
            priority=IncidentPriority(row["priority"]),
            tenant_id=row["tenant_id"],
            case_id=row["case_id"],
            status=row["status"],
            assignee=row["assignee"],
            team=row["team"] or "SOC_TIER_1",
            alert_ids=tuple(json.loads(row["alert_ids_json"] or "[]")),
            tasks=tuple(tasks),
            actions=tuple(actions),
            sla_deadline=row["sla_deadline"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
