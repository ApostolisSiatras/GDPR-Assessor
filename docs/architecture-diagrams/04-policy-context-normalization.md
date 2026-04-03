# Module: Policy Context Normalization (`policy_engine/context.py`, `site_inspector.py`)

## A) Module Architecture Diagram
```mermaid
flowchart LR
  A1[answers dict] --> C0[build_llm_context]
  A2[assessment dict] --> C0

  subgraph Helpers[context.py helpers]
    H1[_clean_text/_sanitize_value]
    H2[_is_placeholder_text/_split_values]
    H3[_answer_by_hint/_listify]
    H4[_humanize_value]
  end

  C0 --> H1
  C0 --> H2
  C0 --> H3
  C0 --> H4

  C0 --> W1[inspect_website(raw_url)]
  W1 --> W2[_normalize_url -> requests.get -> cookie/banner signals]

  C0 --> O1[org block]
  C0 --> O2[processing/lawful bases/processors/transfers/retention/security]
  C0 --> O3[cookies/site inspection/cookie_audit]
```

## B) Function-Level Execution Flow
```mermaid
flowchart TD
  F1[build_llm_context(answers,assessment)] --> F2[question_context from *_context fields]
  F1 --> F3[website_value via _answer_by_hint]
  F3 --> F4[inspection = inspect_website]

  F1 --> F5[profile = assessment.org_profile or answers.company_profile]
  F5 --> F6[org_name/sector/country via _clean_text fallbacks]
  F5 --> F7[dpo resolution from dpo_name or Q-GAP-001]
  F5 --> F8[contact from profile email/phone or Q-GAP-027]

  F1 --> F9[processors/transfers fallback chain]
  F1 --> F10[lawful_bases fallback chain]
  F1 --> F11[retention/security/register_controls/transfer_controls]
  F1 --> F12[cookies merge with site inspection reasons]

  F12 --> F13[return canonical context dict]
```

## C) Data Flow
```mermaid
flowchart LR
  I1[answers with Q-IDs + profile] --> N1[_clean_text/_sanitize_value/_split_values]
  I2[assessment sections/key_facts/cookies/transfers] --> N2[fallback merge logic]
  I3[site_inspector result] --> N3[site_inspection block]

  N1 --> O1[org{name,sector,country,dpo,contact,website}]
  N2 --> O2[processing_register/lawful_bases/processors/transfers/retention/security_measures]
  N3 --> O3[cookies + banner + reachability]

  O1 --> C[final context JSON]
  O2 --> C
  O3 --> C
```

## D) Score Calculation
- Not applicable. This module normalizes and enriches context; it does not compute numeric scores.
