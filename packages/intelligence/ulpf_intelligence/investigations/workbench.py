"""Investigation Workbench Case Management for ULPF Phase 8."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime

from ulpf_intelligence.errors import CaseStateError
from ulpf_intelligence.models.events import AnalystNote, InvestigationCase
from ulpf_intelligence.models.provenance import AlertSeverity, CaseStatus

VALID_CASE_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.OPEN: {CaseStatus.IN_PROGRESS, CaseStatus.CLOSED},
    CaseStatus.IN_PROGRESS: {CaseStatus.CONTAINED, CaseStatus.RESOLVED, CaseStatus.CLOSED},
    CaseStatus.CONTAINED: {CaseStatus.RESOLVED, CaseStatus.IN_PROGRESS, CaseStatus.CLOSED},
    CaseStatus.RESOLVED: {CaseStatus.CLOSED, CaseStatus.IN_PROGRESS},
    CaseStatus.CLOSED: {CaseStatus.OPEN},  # Reopen
}


class InvestigationWorkbench:
    """Thread-safe backend managing security incident investigation cases and analyst notes."""

    def __init__(self) -> None:
        # case_id -> InvestigationCase
        self._cases: dict[str, InvestigationCase] = {}
        self._lock = threading.Lock()

    def create_case(
        self,
        title: str,
        description: str = "",
        created_by: str = "analyst",
        priority: AlertSeverity = AlertSeverity.MEDIUM,
        severity: AlertSeverity | None = None,
        initial_event_ids: list[str] | None = None,
        initial_detection_ids: list[str] | None = None,
        initial_detections: list[str] | None = None,
        assignee: str | None = None,
        tenant_id: str | None = None,
    ) -> InvestigationCase:
        """Create a new security investigation case."""
        from ulpf_intelligence.models.events import TimelineEntry

        now_iso = datetime.now(UTC).isoformat()
        case_id = f"case-{uuid.uuid4().hex[:8]}"
        effective_sev = severity or priority

        dets = initial_detection_ids or initial_detections or []

        initial_timeline = [
            TimelineEntry(
                entry_id=f"tl-{uuid.uuid4().hex[:8]}",
                timestamp=now_iso,
                event_type="CASE_CREATED",
                description=f"Investigation case '{title}' created by {created_by}",
                source_id="workbench",
            )
        ]

        case = InvestigationCase(
            case_id=case_id,
            title=title,
            description=description,
            status=CaseStatus.OPEN,
            priority=effective_sev,
            severity=effective_sev,
            created_by=created_by,
            assignee=assignee,
            created_at=now_iso,
            updated_at=now_iso,
            event_ids=initial_event_ids or [],
            detection_ids=list(dets),
            timeline=initial_timeline,
            tenant_id=tenant_id,
        )

        with self._lock:
            self._cases[case_id] = case
            return case

    def update_status(
        self,
        case_id: str,
        new_status: CaseStatus,
        analyst: str = "analyst",
        user_id: str | None = None,
    ) -> InvestigationCase:
        """Transition case status adhering to the lifecycle state machine."""
        now_iso = datetime.now(UTC).isoformat()
        author = user_id or analyst
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                raise CaseStateError(f"Case '{case_id}' not found")

            valid_next = VALID_CASE_TRANSITIONS.get(case.status, set())
            if new_status not in valid_next:
                raise CaseStateError(
                    f"Invalid case state transition from '{case.status.value}' to '{new_status.value}'"
                )

            case.status = new_status
            case.updated_at = now_iso
            case.notes.append(
                AnalystNote(
                    note_id=f"note-{uuid.uuid4().hex[:8]}",
                    author=author,
                    content=f"Case status transitioned to {new_status.value}",
                    created_at=now_iso,
                )
            )
            return case

    def update_case_status(
        self,
        case_id: str,
        new_status: CaseStatus,
        user_id: str | None = None,
        analyst: str | None = None,
    ) -> InvestigationCase:
        """Convenience alias for update_status."""
        return self.update_status(case_id, new_status, analyst=analyst or user_id or "analyst")

    def add_note(
        self,
        case_id: str,
        author: str,
        content: str,
        tagged_entities: tuple[str, ...] = (),
    ) -> AnalystNote:
        """Append an immutable analyst note to the case."""
        now_iso = datetime.now(UTC).isoformat()
        note = AnalystNote(
            note_id=f"note-{uuid.uuid4().hex[:8]}",
            author=author,
            content=content,
            created_at=now_iso,
            tagged_entities=tagged_entities,
        )

        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                raise CaseStateError(f"Case '{case_id}' not found")

            case.notes.append(note)
            case.updated_at = now_iso
            for ent in tagged_entities:
                if ent not in case.entity_ids:
                    case.entity_ids.append(ent)
            return note

    def add_analyst_note(
        self,
        case_id: str,
        author: str,
        content: str,
        tagged_entities: tuple[str, ...] = (),
    ) -> AnalystNote:
        """Convenience alias for add_note."""
        return self.add_note(case_id, author, content, tagged_entities=tagged_entities)

    def link_evidence(
        self,
        case_id: str,
        event_ids: list[str] | None = None,
        detection_ids: list[str] | None = None,
        entity_ids: list[str] | None = None,
    ) -> InvestigationCase:
        """Link evidence, detections, or entities to an open investigation."""
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                raise CaseStateError(f"Case '{case_id}' not found")

            if event_ids:
                for eid in event_ids:
                    if eid not in case.event_ids:
                        case.event_ids.append(eid)
            if detection_ids:
                for did in detection_ids:
                    if did not in case.detection_ids:
                        case.detection_ids.append(did)
            if entity_ids:
                for ent in entity_ids:
                    if ent not in case.entity_ids:
                        case.entity_ids.append(ent)

            case.updated_at = datetime.now(UTC).isoformat()
            return case

    def link_detection_evidence(
        self,
        case_id: str,
        detection_id: str,
        linked_by: str | None = None,
    ) -> InvestigationCase:
        """Convenience alias for linking detection evidence."""
        return self.link_evidence(case_id, detection_ids=[detection_id])

    def get_case(self, case_id: str) -> InvestigationCase | None:
        with self._lock:
            return self._cases.get(case_id)

    def list_cases(
        self,
        tenant_id: str | None = None,
        status: CaseStatus | None = None,
    ) -> list[InvestigationCase]:
        with self._lock:
            cases = list(self._cases.values())
            if tenant_id:
                cases = [c for c in cases if c.tenant_id == tenant_id]
            if status:
                cases = [c for c in cases if c.status == status]
            return cases
