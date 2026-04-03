# Module: Runtime State + Persistence (`runtime_store.py`, `policy_engine/storage.py`)

## A) Module Architecture Diagram
```mermaid
flowchart LR
  FSess[Flask session] --> SID[runtime_session_id]
  SID --> RS[RuntimeSessionStore._store[sid]]

  RS --> B1[bucket.assessments]
  RS --> B2[bucket.module_reports]
  RS --> B3[bucket.official_policies]
  RS --> B4[bucket.official_policy_current]
  RS --> B5[bucket.last_seen]

  APP[app.py routes] --> RS

  subgraph StorageHelpers[policy_engine/storage.py]
    H1[hash_text]
    H2[write_policy_text]
    H3[read_policy_text]
  end
```

## B) Function-Level Execution Flow
```mermaid
flowchart TD
  L1[before_request cleanup] --> L2[RuntimeSessionStore.cleanup(now)]
  L2 --> L3[remove expired sid buckets by ttl_seconds]

  L4[route reads/writes runtime data] --> L5[bucket(session, create=True)]
  L5 --> L6{runtime_session_id exists?}
  L6 -->|No| L7[_ensure_session_id -> uuid4]
  L6 -->|Yes| L8[reuse sid]
  L7 --> L9[create bucket when missing]
  L8 --> L9
  L9 --> L10[update last_seen]

  L11[logout/reset/fresh login] --> L12[drop_bucket(session)]
  L12 --> L13[delete _store[sid] + pop runtime_session_id]
```

## C) Data Flow
```mermaid
flowchart LR
  A1[assessment submit] --> W1[save_assessment_files]
  W1 --> W2[runtime_store.assessments[mode] = answers+assessment+markdown]
  W1 --> W3[session.assessments[mode] = meta]

  A2[module report generation] --> W4[runtime_store.module_reports[mode]]
  A3[official policy generation] --> W5[runtime_store.official_policies[run_id]]
  W5 --> W6[session.official_policy_run = run_id]

  R1[results/download routes] --> R2[read runtime bucket entries]
  R2 --> R3[render or export response]
```

## D) Score Calculation
- Not applicable. This module stores ephemeral runtime artifacts.
