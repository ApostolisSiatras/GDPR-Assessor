# Ambiguities / Important Notes

1. `weights` and `map` fields exist in schema questions (especially `dpia(1.1)`), but current scoring implementation in `AssessmentBuilder` does **not** consume them.
2. `validators.py` provides validation helpers but is not currently wired into the active route pipeline in `app.py`.
3. `policy_engine/official_policy.py` includes disk-based persistence (`save_official_policy`, `create_official_policy`, `load_official_policy`), while current Flask runtime path stores generated policy artifacts in memory buckets.
4. `dpia.json` remains available for CLI mode, but web routes actively expose `dpia11` and `gap`.
