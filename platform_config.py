# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

"""
EL: Κεντρική διαχείριση ρυθμίσεων εφαρμογής.
EN: Centralized application configuration management.

EL: Το module διαβάζει τιμές από environment variables και επιστρέφει
ένα immutable configuration object για να αποφεύγεται διάσπαρτη λογική
ρυθμίσεων μέσα στο web layer.

EN: This module reads environment variables and returns an immutable
configuration object so runtime settings are not spread across the web layer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformConfig:
    """
    EL: Immutable container με τις κρίσιμες runtime ρυθμίσεις της πλατφόρμας.
    EN: Immutable container holding critical runtime platform settings.
    """

    secret_key: str
    platform_username: str
    platform_password: str
    report_access_token: str | None
    session_runtime_ttl_seconds: int


def _to_positive_int(raw_value: str | None, fallback: int) -> int:
    """
    EL: Κάνει ασφαλές parse ενός θετικού ακεραίου για runtime ρυθμίσεις.
    EN: Safely parses a positive integer for runtime settings.
    """

    if not raw_value:
        return fallback
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


def load_platform_config() -> PlatformConfig:
    """
    EL: Φορτώνει τις ρυθμίσεις περιβάλλοντος με ασφαλή defaults για local dev.
    EN: Loads environment settings with safe defaults for local development.
    """

    return PlatformConfig(
        secret_key=os.environ.get("APP_SECRET_KEY", "gdpr-dpia-secret"),
        platform_username=os.environ.get("PLATFORM_USERNAME", "Tolis"),
        platform_password=os.environ.get("PLATFORM_PASSWORD", "Siatras"),
        report_access_token=os.environ.get("REPORT_ACCESS_TOKEN"),
        session_runtime_ttl_seconds=_to_positive_int(
            os.environ.get("SESSION_RUNTIME_TTL_SECONDS"),
            fallback=43200,
        ),
    )
