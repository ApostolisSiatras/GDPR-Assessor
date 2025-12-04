# GDPR Data Protection Policy
**Company:** {{company.name}}  
**Jurisdiction:** {{company.jurisdiction}} | **Industry:** {{company.industry}} | **Size:** {{company.size}}  
**Last updated:** {{generated_at}}

---
## 1. Purpose and Scope
Owner: {{owners.governance | default:"DPO"}} • Review cycle: {{review.governance | default:"Annual"}}
This policy establishes how {{company.name}} complies with the General Data Protection Regulation (GDPR). It applies to all personal data processing activities under our control, including activities performed by processors on our behalf.

**Processing purposes:** {{#if purposes}}{{purposes}}{{else}}[Not specified]{{/if}}  
**Data subjects:** {{#if data_subjects}}{{data_subjects}}{{else}}[Not specified]{{/if}}  
**Data categories:** {{#if data_categories}}{{data_categories}}{{else}}[Not specified]{{/if}}

---
## 2. Roles and Responsibilities (Art. 24–25)
Owner: {{owners.governance | default:"DPO"}} • Review cycle: {{review.governance | default:"Annual"}}
- **Controller:** {{roles.controller | default:"[Not specified]"}}
- **Processor(s):** {{roles.processors | default:"[Not specified]"}}
- **DPO:** {{roles.dpo | default:"[Not specified]"}} (Art. 37)

---
## 3. Lawfulness, Fairness, Transparency (Arts. 5–7, 12–14)
Owner: {{owners.legal | default:"Legal"}} • Review cycle: {{review.legal | default:"Annual"}}
- **Legal bases used:** {{#if legal_bases}}{{legal_bases}}{{else}}[Not specified]{{/if}} (Art. 6)
- **Privacy notices:** {{privacy_notices_status}} (Arts. 12–14)
- **Consent management (if used):** {{consent_status}} (Art. 7)

---
## 4. Data Minimization, Accuracy, Retention (Art. 5(1)(c)-(e))
Owner: {{owners.governance | default:"DPO"}} • Review cycle: {{review.governance | default:"Annual"}}
- **Minimization:** {{minimization_status}}
- **Accuracy procedures:** {{accuracy_status}}
- **Maximum retention:** {{retention_months | default:"[Not specified]"}} months
- **Deletion/archiving routines:** {{deletion_status}}

---
## 5. Records of Processing (Art. 30)
Owner: {{owners.governance | default:"DPO"}} • Review cycle: {{review.governance | default:"Annual"}}
RoPA status: {{ropa_status}}. The record includes purposes, categories, recipients, transfers, retention periods, and security measures as required by Art. 30.

---
## 6. Security of Processing (Art. 32)
Owner: {{owners.security | default:"CISO"}} • Review cycle: {{review.security | default:"Annual"}}
Overall security posture: {{security_overall}}.

**Technical and organizational measures implemented:**
{{#if security_controls}}
- {{security_controls}}
{{else}}
- [Not specified]
{{/if}}

**Encryption:** at rest = {{enc_at_rest}}; in transit = {{enc_in_transit}}.  
**Testing & assurance:** {{testing_assurance}}.  
**Logging & monitoring:** {{logging_status}}.  
**Backup & recovery:** {{backup_status}}.

{{#if special_categories}}
> Additional safeguards required due to processing of special categories (Art. 9): DPIA, enhanced access control, encryption at rest, strict retention, and purpose limitation.
{{/if}}

{{#if vulnerable_subjects}}
> Heightened protections for children/vulnerable adults (Recital 38): guardian consent where applicable, age-appropriate notices, and restricted profiling.
{{/if}}

---
## 7. International Transfers (Arts. 44–49)
Owner: {{owners.legal | default:"Legal"}} • Review cycle: {{review.legal | default:"Annual"}}
Transfers outside the EEA: {{transfers_flag}}.  
Safeguards in use: {{transfer_mechanisms | default:"[Not specified]"}}.

{{#if transfers_without_safeguard}}
**Risk Notice:** Some transfers lack adequate safeguards. Actions: implement SCCs/BCRs or cease such transfers until compliant (Arts. 44–49).
{{/if}}

---
## 8. Data Subject Rights (Arts. 12–22)
Owner: {{owners.privacy_ops | default:"Privacy Ops"}} • Review cycle: {{review.privacy_ops | default:"Annual"}}
**Rights supported:** {{#if rights_supported}}{{rights_supported}}{{else}}[Not specified]{{/if}}.  
**Timelines:** {{dsar_timelines}}.  
**Objection/restriction:** {{objection_status}}.  
{{#if adm_present}}**Automated decision-making:** human review available; explainability and contestation processes in place (Art. 22).{{/if}}

---
## 9. DPIA and High-Risk Processing (Art. 35–36)
Owner: {{owners.privacy_ops | default:"Privacy Ops"}} • Review cycle: {{review.privacy_ops | default:"Annual"}}
DPIA practice: {{dpia_status}}.  
Residual risk approach: likelihood={{residual_likelihood}}, impact={{residual_impact}} (Recital 76).  
Consultation with supervisory authority where required (Art. 36).

---
## 10. Vendor and Processor Management (Art. 28)
Owner: {{owners.procurement | default:"Procurement"}} • Review cycle: {{review.procurement | default:"Annual"}}
DPA status: {{dpa_status}}.  
Due diligence artifacts: {{vendor_dd_artifacts}}.  
Audit and oversight: {{vendor_audit_status}}.

---
## 11. Incident and Breach Response (Arts. 33–34)
Owner: {{owners.security | default:"CISO"}} • Review cycle: {{review.security | default:"Annual"}}
Breach response process: {{breach_process_status}}.  
Notification timelines and roles defined in accordance with Arts. 33–34.

---
## 12. Training and Awareness (Art. 39(1)(b))
Owner: {{owners.hr | default:"HR"}} • Review cycle: {{review.hr | default:"Annual"}}
Training status: {{training_status}}. Content covers privacy principles, security practices, and incident reporting.

---
## 13. Governance, Monitoring, and Review
Owner: {{owners.governance | default:"DPO"}} • Review cycle: {{review.governance | default:"Annual"}}
Governance metrics, internal auditing cadence, and continuous improvement activities: {{governance_metrics_status}}.
