# GDPR Assessor

## Overview / Επισκόπηση
- EN: GDPR Assessor is a Flask-based compliance workspace for running DPIA/GAP assessments, cookie audits, AI-assisted module reports, and official policy generation.
- EL: Το GDPR Assessor είναι ένα Flask-based compliance workspace για DPIA/GAP αξιολογήσεις, cookie audits, AI-assisted reports και παραγωγή επίσημης πολιτικής.

## Architecture / Αρχιτεκτονική
- `app.py`: EN: Web entrypoint, routing orchestration, session flow. EL: Κεντρικό web entrypoint και orchestration του flow.
- `gdpr_wizard.py`: EN: Domain models and scoring engine for questionnaires. EL: Domain μοντέλα και scoring engine.
- `cookie_audit.py`: EN: Deep website cookie/compliance scanner. EL: Αναλυτικός scanner cookies και τεχνικών σημάτων.
- `policy_engine/`: EN: Prompt-based policy/report generation and rendering pipeline. EL: Pipeline παραγωγής policy/report και rendering.
- `platform_config.py`: EN: Central runtime configuration loader. EL: Κεντρικός loader ρυθμίσεων runtime.
- `runtime_store.py`: EN: Thread-safe in-memory runtime session state. EL: Thread-safe in-memory state ανά session.

## Data Flow / Ροή Δεδομένων
1. EN: User submits assessment forms (`/assessment/<mode>`). EL: Ο χρήστης υποβάλλει φόρμες αξιολόγησης.
2. EN: Answers are validated and scored by `AssessmentBuilder`. EL: Τα answers γίνονται validate και score από `AssessmentBuilder`.
3. EN: Session runtime store keeps temporary assessment/report artefacts. EL: Το runtime store κρατά προσωρινά artefacts.
4. EN: Results dashboard composes charts, risks, and annex failures. EL: Το dashboard συνθέτει charts, risk matrix και failures.
5. EN: Policy engine builds LLM context and generates official policy exports. EL: Το policy engine δημιουργεί LLM context και εξαγωγές policy.

## Security Notes / Σημειώσεις Ασφαλείας
- EN: Configure `APP_SECRET_KEY`, `PLATFORM_USERNAME`, and `PLATFORM_PASSWORD` in production.
- EL: Ορίστε `APP_SECRET_KEY`, `PLATFORM_USERNAME`, `PLATFORM_PASSWORD` σε production περιβάλλον.

## Local Run / Τοπική Εκτέλεση
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Testing / Δοκιμές
```bash
pytest
```

## Environment Variables / Μεταβλητές Περιβάλλοντος
- `APP_SECRET_KEY`
- `PLATFORM_USERNAME`
- `PLATFORM_PASSWORD`
- `REPORT_ACCESS_TOKEN`
- `SESSION_RUNTIME_TTL_SECONDS`
- `POLICY_ENGINE_MODEL`
- `OLLAMA_URL`

## License / Αδεια
- EN: This project is licensed under Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0).
- EN: License URL: https://creativecommons.org/licenses/by-nc-sa/4.0/
- EL: Το project διατιθεται με αδεια Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0).
- EL: Συνδεσμος αδειας: https://creativecommons.org/licenses/by-nc-sa/4.0/
