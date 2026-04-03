# Module: Configuration + Validation (`platform_config.py`, `policy_engine/config.py`, `validators.py`)

## A) Module Architecture Diagram
```mermaid
flowchart LR
  ENV[Environment variables] --> PC[load_platform_config -> PlatformConfig]
  ENV --> PEC[load_policy_engine_config -> PolicyEngineConfig]

  PC --> APP[app.py runtime settings]
  PEC --> POL[policy_engine constants]

  VAL[validators.py] --> V1[validate_cookie_policy]
  VAL --> V2[validate_transfers]
  VAL --> V3[validate_json Draft7Validator]
```

## B) Function-Level Execution Flow
```mermaid
flowchart TD
  C1[load_platform_config] --> C2[_to_positive_int for SESSION_RUNTIME_TTL_SECONDS]
  C2 --> C3[PlatformConfig(secret,user,pass,token,ttl)]

  C4[load_policy_engine_config] --> C5[ensure output directories]
  C5 --> C8[PolicyEngineConfig(model,prompts,official_dir,pandoc,regex)]

  V1[validate_transfers(ctx,md_text)] --> V2[_detect_non_eea_transfers]
  V2 --> V3{outside EEA and no SCC phrase?}
  V3 -->|Yes| V4[return validation error]
```

## C) Data Flow
```mermaid
flowchart LR
  E1[OS env vars] --> D1[typed config objects]
  D1 --> D2[app/policy runtime constants]

  X1[ctx + markdown] --> V1[validate_cookie_policy/validate_transfers]
  X2[schema + payload] --> V2[validate_json]
  V1 --> O1[list of errors]
  V2 --> O1
```

## D) Score Calculation
- Not applicable. This module handles configuration and validation rules.
