#!/usr/bin/env python3
"""Flask UI for generating access tokens and quick codes."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from flask import Flask, render_template_string, request

import generate


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-change-me")
DEFAULT_SECRET = os.environ.get("LOGIN_TOKEN_SECRET", "gdpr-dpia-secret")


TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Access Code Generator</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: radial-gradient(circle at 20% 20%, #eef2ff, #f8fbff 50%, #ffffff);
      --panel: #ffffff;
      --border: #d4d9e6;
      --accent: #2f6bff;
      --muted: #6b7280;
      --text: #0f172a;
      --code: #0b1021;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: 'Space Grotesk', 'IBM Plex Sans', 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .page {
      max-width: 1080px;
      margin: 0 auto;
    }
    header h1 {
      margin: 0 0 4px;
      font-size: 28px;
    }
    header p {
      margin: 0 0 16px;
      color: var(--muted);
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
      margin-bottom: 16px;
    }
    .steps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }
    .step {
      display: flex;
      gap: 10px;
      align-items: center;
      background: #f6f8ff;
      border: 1px dashed var(--border);
      border-radius: 12px;
      padding: 10px 12px;
    }
    .step .num {
      width: 32px;
      height: 32px;
      display: grid;
      place-items: center;
      border-radius: 10px;
      background: #e5ecff;
      color: var(--accent);
      font-weight: 700;
    }
    form label {
      display: block;
      font-weight: 600;
      margin-bottom: 6px;
    }
    input, select {
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--border);
      padding: 10px 12px;
      font-size: 15px;
    }
    input[type="checkbox"] {
      width: auto;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
    }
    .row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }
    button {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 12px;
      padding: 12px 16px;
      font-weight: 700;
      font-size: 15px;
      cursor: pointer;
      margin-top: 12px;
      box-shadow: 0 10px 30px rgba(47, 107, 255, 0.25);
    }
    button.secondary {
      background: #f3f4f6;
      color: var(--text);
      box-shadow: none;
    }
    .options {
      display: flex;
      gap: 18px;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    .options label {
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 0;
      color: var(--muted);
    }
    .alert {
      background: #fff6f6;
      border: 1px solid #f5b8b8;
      color: #8a1c1c;
      padding: 12px 14px;
      border-radius: 12px;
      margin-bottom: 12px;
    }
    .results h2 {
      margin: 0 0 6px;
    }
    pre {
      background: #0f172a;
      color: #f8fafc;
      padding: 14px;
      border-radius: 12px;
      overflow: auto;
      font-size: 14px;
    }
    .chips {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 8px 0;
    }
    .chip {
      background: #eef2ff;
      color: var(--text);
      padding: 8px 12px;
      border-radius: 999px;
      font-weight: 600;
      border: 1px solid #dde4ff;
    }
    .value {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      margin: 8px 0;
    }
    .muted { color: var(--muted); }
    .copy-btn {
      background: #0b1021;
      color: #fff;
      border-radius: 10px;
      border: 1px solid #1f2937;
      padding: 8px 10px;
      font-weight: 600;
      cursor: pointer;
    }
    .hint {
      color: var(--muted);
      margin: 4px 0 0;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="page">
    <header>
      <h1>Access Code Generator</h1>
      <p>Guide the user through picking a profile, adding an optional reference, and minting tokens or quick codes.</p>
    </header>

    <div class="panel">
      <div class="steps">
        <div class="step"><div class="num">1</div><div>Pick the user profile and optional reference.</div></div>
        <div class="step"><div class="num">2</div><div>Choose how long it should stay valid and what to generate.</div></div>
        <div class="step"><div class="num">3</div><div>Generate and copy the token or quick codes.</div></div>
      </div>

      {% if errors %}
        <div class="alert">
          <strong>Fix these first:</strong>
          <ul>
            {% for error in errors %}
              <li>{{ error }}</li>
            {% endfor %}
          </ul>
        </div>
      {% endif %}

      <form method="post">
        <div class="grid">
          <div>
            <label for="profile">Profile</label>
            <select id="profile" name="profile">
              {% for key, role in profile_map.items() %}
                <option value="{{ key }}" {% if form.profile == key %}selected{% endif %}>{{ key }} → {{ role }}</option>
              {% endfor %}
            </select>
            <div class="hint">Maps to login roles; defaults to auditor.</div>
          </div>
          <div>
            <label for="ref">Reference (optional)</label>
            <input id="ref" name="ref" type="text" placeholder="REF-12345 or session id" value="{{ form.ref }}">
            <div class="hint">If set, the token is scoped to this reference.</div>
          </div>
          <div>
            <label for="minutes">Validity (minutes)</label>
            <input id="minutes" name="minutes" type="number" min="1" max="{{ 24*60 }}" value="{{ form.minutes }}">
            <div class="hint">How long the token or code should remain active.</div>
          </div>
          <div>
            <label for="secret">Signing secret</label>
            <input id="secret" name="secret" type="password" value="{{ form.secret }}">
            <div class="hint">Defaults to LOGIN_TOKEN_SECRET or gdpr-dpia-secret.</div>
          </div>
        </div>

        <div class="options">
          <label><input type="checkbox" name="token_enabled" {% if form.token_enabled %}checked{% endif %}> Generate signed token</label>
          <label><input type="checkbox" name="quick_enabled" {% if form.quick_enabled %}checked{% endif %}> Generate quick codes (BAS/ADV/PRE/ADM)</label>
        </div>
        <button type="submit">Generate</button>
      </form>
    </div>

    {% if result %}
      <div class="panel results">
        <h2>Result</h2>
        <div class="chips">
          <div class="chip">Profile: {{ result.profile }}</div>
          {% if result.ref %}<div class="chip">Reference: {{ result.ref }}</div>{% endif %}
          <div class="chip">Expires: {{ result.expires_label }}</div>
          <div class="chip">Remaining: {{ result.remaining }}</div>
        </div>

        {% if result.token %}
          <div class="value">
            <strong>Token</strong>
            <button class="copy-btn" type="button" onclick="copyText('token-value')">Copy</button>
          </div>
          <pre id="token-value">{{ result.token }}</pre>
        {% endif %}

        {% if result.payload_json %}
          <div class="value"><strong>Payload (before signing)</strong></div>
          <pre>{{ result.payload_json }}</pre>
        {% endif %}

        {% if result.quick_codes %}
          <div class="value"><strong>Quick codes</strong></div>
          <div class="chips">
            {% for role, code in result.quick_codes.items() %}
              <div class="chip">{{ role }}: {{ code }}</div>
            {% endfor %}
          </div>
        {% endif %}
      </div>
    {% else %}
      <div class="panel">
        <div class="muted">Use the form above to generate a token and quick codes that include your reference.</div>
      </div>
    {% endif %}
  </div>
  <script>
    function copyText(id) {
      const el = document.getElementById(id);
      if (!el) return;
      const text = el.innerText;
      navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard');
      }).catch(() => {
        alert('Press Ctrl/Cmd+C to copy manually');
      });
    }
  </script>
</body>
</html>
"""


def _format_expires_label(expires_at: datetime) -> str:
    return expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@app.route("/", methods=["GET", "POST"])
def index():
    errors: list[str] = []
    form = {
        "profile": (request.form.get("profile") or request.args.get("profile") or "auditor").strip(),
        "ref": request.form.get("ref") or request.args.get("ref") or "",
        "minutes": request.form.get("minutes") or request.args.get("minutes") or "60",
        "secret": request.form.get("secret") or request.args.get("secret") or DEFAULT_SECRET,
        "token_enabled": request.method != "POST" or ("token_enabled" in request.form),
        "quick_enabled": request.method != "POST" or ("quick_enabled" in request.form),
    }

    result: dict | None = None

    if request.method == "POST":
        try:
            minutes_val = int(form["minutes"])
            if minutes_val <= 0:
                errors.append("Minutes must be greater than zero.")
        except ValueError:
            errors.append("Minutes must be a valid integer.")
            minutes_val = 0

        if not (form["token_enabled"] or form["quick_enabled"]):
            errors.append("Choose at least one output: token or quick codes.")

        if not errors:
            profile = form["profile"] or "auditor"
            ref = form["ref"].strip() or None
            payload = generate.build_payload(profile, ref, minutes_val)
            expires_at = datetime.fromisoformat(payload["exp"])
            token = generate.generate_token(profile, ref, minutes_val, form["secret"]) if form["token_enabled"] else None
            quick_codes = generate.generate_quick_codes() if form["quick_enabled"] else None

            result = {
                "profile": profile,
                "ref": ref,
                "expires_label": _format_expires_label(expires_at),
                "remaining": generate.format_remaining((expires_at - datetime.now(timezone.utc)).total_seconds()),
                "token": token,
                "quick_codes": quick_codes,
                "payload_json": json.dumps(payload, indent=2),
            }

    return render_template_string(
        TEMPLATE,
        form=form,
        errors=errors,
        result=result,
        profile_map=generate.PROFILE_MAP,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
