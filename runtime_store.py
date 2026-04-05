# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

"""
EL: Thread-safe in-memory αποθήκη runtime δεδομένων ανά session.
EN: Thread-safe in-memory runtime store keyed by session.

EL: Το layer αυτό απομονώνει την προσωρινή κατάσταση (assessments/reports)
ώστε το web layer να μην διαχειρίζεται απευθείας mutable global dicts.

EN: This layer isolates temporary state (assessments/reports) so the web
layer does not manage mutable global dictionaries directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any, Dict, MutableMapping, Optional
from uuid import uuid4


@dataclass
class RuntimeStoreConfig:
    """
    EL: Ρυθμίσεις διάρκειας ζωής runtime session buckets.
    EN: TTL configuration for runtime session buckets.
    """

    ttl_seconds: int = 43200


class RuntimeSessionStore:
    """
    EL: Διαχειρίζεται ephemeral runtime state ανά ενεργό session.
    EN: Manages ephemeral runtime state per active session.

    EL: Κύριοι consumers είναι τα routes του app.py που αποθηκεύουν
    assessments, module reports και generated policies.

    EN: Main consumers are app.py routes storing assessments,
    module reports, and generated policies.
    """

    def __init__(self, config: RuntimeStoreConfig | None = None) -> None:
        self._config = config or RuntimeStoreConfig()
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    @staticmethod
    def _mark_session_modified(session_state: MutableMapping[str, Any]) -> None:
        """
        EL: Σηματοδοτεί Flask session ως changed όταν υπάρχει το attribute.
        EN: Marks Flask session as modified when the attribute exists.
        """

        if hasattr(session_state, "modified"):
            setattr(session_state, "modified", True)

    def cleanup(self, now: Optional[datetime] = None) -> None:
        """
        EL: Απομακρύνει buckets που έχουν λήξει βάσει TTL.
        EN: Removes expired runtime buckets based on TTL.
        """

        current = now or datetime.now(UTC)
        with self._lock:
            expired: list[str] = []
            for sid, payload in self._store.items():
                last_seen = payload.get("last_seen")
                if not isinstance(last_seen, datetime):
                    expired.append(sid)
                    continue
                age = (current - last_seen).total_seconds()
                if age >= self._config.ttl_seconds:
                    expired.append(sid)
            for sid in expired:
                self._store.pop(sid, None)

    def _ensure_session_id(self, session_state: MutableMapping[str, Any]) -> str:
        sid = session_state.get("runtime_session_id")
        if sid:
            return str(sid)
        new_sid = uuid4().hex
        session_state["runtime_session_id"] = new_sid
        self._mark_session_modified(session_state)
        return new_sid

    def bucket(
        self,
        session_state: MutableMapping[str, Any],
        *,
        create: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        EL: Επιστρέφει το runtime bucket της τρέχουσας session.
        EN: Returns the runtime bucket for the current session.
        """

        self.cleanup()
        with self._lock:
            sid = session_state.get("runtime_session_id")
            if not sid and not create:
                return None
            if not sid:
                sid = self._ensure_session_id(session_state)
            sid = str(sid)
            bucket = self._store.get(sid)
            if bucket is None and create:
                bucket = {
                    "last_seen": datetime.now(UTC),
                    "assessments": {},
                    "module_reports": {},
                    "official_policies": {},
                    "official_policy_current": None,
                }
                self._store[sid] = bucket
            if bucket is not None:
                bucket["last_seen"] = datetime.now(UTC)
            return bucket

    def drop_bucket(self, session_state: MutableMapping[str, Any]) -> None:
        """
        EL: Διαγράφει runtime state για logout/reset και καθαρίζει session id.
        EN: Deletes runtime state on logout/reset and clears session id.
        """

        with self._lock:
            sid = session_state.get("runtime_session_id")
            if sid:
                self._store.pop(str(sid), None)
            session_state.pop("runtime_session_id", None)
            self._mark_session_modified(session_state)

    def assessments(self, session_state: MutableMapping[str, Any]) -> Dict[str, Dict[str, Any]]:
        bucket = self.bucket(session_state, create=True)
        return bucket["assessments"] if bucket else {}

    def module_reports(self, session_state: MutableMapping[str, Any]) -> Dict[str, Dict[str, Any]]:
        bucket = self.bucket(session_state, create=True)
        return bucket["module_reports"] if bucket else {}

    def official_policies(self, session_state: MutableMapping[str, Any]) -> Dict[str, Dict[str, Any]]:
        bucket = self.bucket(session_state, create=True)
        return bucket["official_policies"] if bucket else {}

    def current_policy_run_id(self, session_state: MutableMapping[str, Any]) -> Optional[str]:
        bucket = self.bucket(session_state, create=False)
        if not bucket:
            return None
        run_id = bucket.get("official_policy_current")
        return run_id if isinstance(run_id, str) and run_id else None
