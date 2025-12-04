from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_TEMPERATURE = 0.2


def run_ollama(prompt: str, model: str = DEFAULT_MODEL, options: Optional[Dict[str, Any]] = None, stream: bool = False) -> str:
    """Call the local Ollama REST API and return the generated text."""
    payload: Dict[str, Any] = {"model": model, "prompt": prompt, "stream": stream}
    opts = {"temperature": DEFAULT_TEMPERATURE}
    if options:
        opts.update(options)
    payload["options"] = opts
    try:
        response = requests.post(OLLAMA_URL, json=payload, stream=stream, timeout=60)
    except requests.RequestException as exc:  # pragma: no cover - network failure path
        raise RuntimeError("Failed to reach local Ollama service on 11434.") from exc
    if response.status_code != 200:
        snippet = response.text[:200]
        raise RuntimeError(f"Ollama request failed ({response.status_code}): {snippet}")
    if stream:
        chunks = []
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
    data = response.json()
    return data.get("response", "")


def json_block(text: str) -> Dict[str, Any]:
    """Extract the last JSON object from the model output and parse it."""
    if not text:
        raise ValueError("No text to parse for JSON block.")
    depth = 0
    start = None
    end = None
    for idx in range(len(text) - 1, -1, -1):
        char = text[idx]
        if char == "}":
            if depth == 0:
                end = idx + 1
            depth += 1
        elif char == "{":
            depth -= 1
            if depth == 0:
                start = idx
                break
    if start is None or end is None:
        raise ValueError("No JSON object found in model output.")
    block = text[start:end]
    try:
        return json.loads(block)
    except json.JSONDecodeError as exc:
        raise ValueError("Model output did not contain valid JSON.") from exc
