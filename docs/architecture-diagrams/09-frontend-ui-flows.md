# Module: Frontend UI + Frontend↔Backend Flows (`templates/*.html`)

## A) Module Architecture Diagram
```mermaid
flowchart LR
  L[layout.html] --> H[home.html]
  L --> A[assessment_form.html]
  L --> R[results.html]
  L --> C[cookie_audit.html]
  L --> P[official_policy.html]
  L --> LG[login.html]
  L --> RA[report_access.html]

  H --> E1[POST /access-control]
  H --> E2[POST /reset]
  H --> E3[GET /assessment/<mode>]

  A --> E4[POST /assessment/<mode>]
  A --> E5[fetch POST /assessment/<mode>/autofill]

  R --> E6[POST /module-report/<mode>]
  R --> E7[GET /module-report/<mode>/download.<fmt>]
  R --> E8[POST /cookie-audit/include]
  R --> E9[GET /reports/<mode>/export]

  C --> E10[POST /cookie-audit]
  C --> E11[POST /cookie-audit/include]

  P --> E12[POST /official-policy]
  P --> E13[POST /official-policy/profile]
  P --> E14[POST /official-policy/comments]
  P --> E15[GET /official-policy/download/<run_id>]

  LG --> E16[POST /login]
  RA --> E17[POST /report-access]
```

## B) Function-Level Interaction Sequence
```mermaid
sequenceDiagram
  participant U as User
  participant T as Template JS/Form
  participant A as app.py route
  participant S as Service layer
  participant ST as Session/Runtime store

  U->>T: Submit assessment form
  T->>A: POST /assessment/<mode>
  A->>S: parse_answers + run_assessment
  S->>ST: save_assessment_files
  A-->>U: redirect /results

  U->>T: Click Auto-fill
  T->>A: fetch POST /assessment/<mode>/autofill {variant}
  A->>S: build_autofill_answers + run_assessment
  S->>ST: save_assessment_files
  A-->>T: JSON redirect URL
  T-->>U: window.location.href = /results

  U->>T: Generate policy
  T->>A: POST /official-policy
  A->>S: combined_assessment_inputs + generate_official_policy_sections
  S->>ST: store policy artifacts
  A-->>U: redirect /official-policy

  U->>T: Click DOCX/PDF download
  T->>A: GET download endpoint
  A->>S: render/export bytes
  A-->>U: file stream
```

## C) Data Flow
```mermaid
flowchart LR
  I1[HTML form fields and buttons] --> H1[POST body / JSON]
  H1 --> B1[Flask route handlers]

  B1 --> O1[render_template state/errors/progress]
  B1 --> O2[render_template results with chart_data + matrices + reports]
  O2 --> JS1[results.js chartPayload]
  JS1 --> C1[Chart.js visualizations]

  B1 --> O3[send_file exports zip/md/html/pdf/docx]
  O3 --> DL[browser download]
```

## D) Score Calculation
- Not applicable in frontend. UI renders scores and analytics calculated on backend.
