# Access code generator

Standalone helper to mint login tokens or quick codes. Includes a CLI, Tk UI, and an optional Flask web UI.

## Web UI (Flask)

```bash
pip install flask
python tools/access_codes/flask_app.py  # http://localhost:5001 by default
# or
FLASK_APP=tools/access_codes/flask_app.py flask run --reload
```

- Simple guided page that accepts a reference, profile, validity minutes, and signing secret.
- Toggle signed token and/or quick code generation; shows the payload before signing and expiry info.
- Use the copy button next to the token or grab the quick codes displayed as chips.

## Graphical UI (with persistence)

```bash
# Launch the UI directly
python tools/access_codes/ui.py

# Launch the UI, pre-filling defaults if you want
python tools/access_codes/generate.py --ui --profile auditor --minutes 60 --ref REF-12345
```

- Generates tokens and quick codes with the configured expiry.
- Shows remaining time for every generated password/code and keeps it updated.
- Saves everything to `tools/access_codes/generate.state.json` so timers resume after a restart or system shutdown.
- Use “Clear expired” in the UI to prune expired rows; “Copy selected” copies a value to the clipboard.

## CLI usage

```bash
# Generate a token for the Advanced role (profile "auditor") with a 60 minute expiry
python tools/access_codes/generate.py --profile auditor --minutes 60 --ref REF-12345

# Generate only the quick codes (BAS/ADV/PRE/ADM style)
python tools/access_codes/generate.py --only-quick
```

### Notes
- Profiles map to roles: `viewer`→Basic, `auditor`→Advanced, `editor`→Premium, `owner`→Admin.
- The signature uses `LOGIN_TOKEN_SECRET` (or defaults to `gdpr-dpia-secret`), but the current app only reads the payload portion.
- The reference (`ref`) should match the login page reference if you want the token scoped to a specific session.
