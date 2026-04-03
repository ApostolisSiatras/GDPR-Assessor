# Module: Rendering/Export Pipeline (`policy_engine/rendering.py`)

## A) Module Architecture Diagram
```mermaid
flowchart LR
  MD[markdown text] --> H[markdown_to_html]
  MD --> P1[markdown_to_pdf_bytes(policy_number,signature)]
  MD --> P2[markdown_to_pdf_report(title,subtitle)]
  MD --> D[markdown_to_docx_bytes(title,subtitle)]

  D --> C1{python-docx available?}
  C1 -->|Yes| C2[Document API build]
  C1 -->|No and pandoc| C3[convert_markdown_with_pandoc('docx')]
  C1 -->|No and no pandoc| C4[RuntimeError]

  P1 --> SEC[StandardEncryption using policy_number]
```

## B) Function-Level Execution Flow
```mermaid
flowchart TD
  D0[markdown_to_docx_bytes] --> D1[try import docx.Document]
  D1 -->|import error| D2{PANDOC_PATH exists?}
  D2 -->|Yes| D3[convert_markdown_with_pandoc]
  D2 -->|No| D4[raise RuntimeError]

  D1 -->|ok| D5[create Document + title/subtitle/timestamp]
  D5 --> D6[for each markdown line]
  D6 --> D7{heading?}
  D7 --> D8[add_heading(level)]
  D6 --> D9{bullet/numbered?}
  D9 --> D10[add List Bullet/List Number]
  D6 --> D11[add paragraph]
  D8 --> D12[_markdown_to_docx_text inline cleanup]
  D10 --> D12
  D11 --> D12
  D12 --> D13[save BytesIO and return bytes]
```

## C) Data Flow
```mermaid
flowchart LR
  R1[runtime module report text] --> E1[download_module_report(fmt)]
  R2[runtime official policy artifacts] --> E2[download_official_policy(fmt)]

  E1 -->|md| O1[utf-8 bytes]
  E1 -->|pdf| O2[markdown_to_pdf_report bytes]
  E1 -->|docx| O3[markdown_to_docx_bytes]

  E2 -->|md/html| O4[text bytes]
  E2 -->|pdf| O5[pdf bytes]
  E2 -->|docx| O6[markdown_to_docx_bytes]

  O1 --> S[send_file BytesIO]
  O2 --> S
  O3 --> S
  O4 --> S
  O5 --> S
  O6 --> S
```

## D) Score Calculation
- Not applicable. This module performs text rendering/export only.
