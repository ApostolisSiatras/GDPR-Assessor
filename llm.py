"""
EL: Adapter για κλήσεις προς το τοπικό Ollama endpoint.
EN: Adapter for calls to the local Ollama endpoint.

EL: Το module αυτό απομονώνει HTTP επικοινωνία και parsing ώστε οι υπόλοιπες
υπηρεσίες (policy_engine, reports) να εξαρτώνται από ένα σταθερό API.

EN: This module isolates HTTP transport and parsing so downstream services
(policy_engine, reports) can depend on a stable API.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_TEMPERATURE = 0.2
REQUEST_TIMEOUT_SECONDS = 60


def run_ollama(
    prompt: str,
    model: str = DEFAULT_MODEL,
    options: Optional[Dict[str, Any]] = None,
    stream: bool = False,
) -> str:
    """
    EL: Εκτελεί prompt στο Ollama API και επιστρέφει το concatenated μοντέλο output.
    EN: Executes a prompt against Ollama API and returns concatenated model output.
    """

    payload: Dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": stream,
    }
    merged_options = {"temperature": DEFAULT_TEMPERATURE}
    if options:
        merged_options.update(options)
    payload["options"] = merged_options

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            stream=stream,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:  # pragma: no cover - EL: network αστοχία / EN: network failure path
        raise RuntimeError("Failed to reach local Ollama service on port 11434.") from exc

    if response.status_code != 200:
        snippet = response.text[:200]
        raise RuntimeError(f"Ollama request failed ({response.status_code}): {snippet}")

    if stream:
        chunks: list[str] = []
        for line in response.iter_lines():
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            chunks.append(data.get("response", ""))
            if data.get("done"):
                break
        return "".join(chunks)

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("Ollama returned a non-JSON response.") from exc
    return data.get("response", "")
