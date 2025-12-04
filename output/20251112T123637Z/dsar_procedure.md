# DSAR Handling Procedure
Last updated: 2025-11-12

## Purpose
This procedure outlines the steps to be taken when handling Data Subject Access Requests (DSARs) in accordance with the General Data Protection Regulation (GDPR).

## Intake & Verification
1. Identify and verify the requestor's identity.
2. Confirm that the request is a DSAR under GDPR.
3. Check if the request is time-barred or incomplete.

### Safeguards
* Lawful bases: Consent, Contract, Legal Obligation (declared in ctx.lawful_bases.declared)
* Processors: Controller, Joint Controller, Processor (listed in ctx.processors)

## Assessment & Coordination
1. Determine the scope of the request.
2. Identify relevant data and systems involved.
3. Assess the feasibility of providing the requested information.

### Safeguards
* Transfers: Adequacy, SCC, BCR (mechanisms listed in ctx.transfers[0].mechanisms)
* Retention: 1 month retention period (defined in ctx.retention.months)

## Response Content
1. Provide a response within the specified timeframe.
2. Include all requested information, excluding sensitive data.
3. Offer an explanation for any withheld or redacted information.

### Safeguards
* Rights: Data subject's rights under GDPR (referenced in ctx.sections.E.Rights)
* Security controls: Implemented security measures to protect personal data (listed in ctx.security_measures)

## Timelines & Escalations
1. Respond to DSARs within 30 days.
2. Escalate complex or high-priority requests to the Data Protection Officer (DPO).

### Safeguards
* Risk rating: Strong risk rating (defined in ctx.risk.rating)
* Earned scores: A.Context, B.Stakeholders, B.Transfers, C.Risk, D.Security, E.Rights, F.Residual (listed in ctx.sections)

## Recordkeeping
1. Maintain a record of all DSARs received.
2. Document the response and any actions taken.

### Safeguards
* Processor details: Controller, Joint Controller, Processor (listed in ctx.processors)
* Transfer mechanisms: Adequacy, SCC, BCR (mechanisms listed in ctx.transfers[0].mechanisms)

## Contact
For more information or to submit a DSAR, please contact our Data Protection contact at [insert contact details].

### Safeguards
* Organisation's name and sector: Redacted Organisation, Not provided (defined in ctx.org.name and ctx.org.sector)
* Website: Not available (defined in ctx.org.website)
