# Rules of Engagement

> Fill in every field in brackets and delete this note. Nothing starts until both parties have signed. This template is a working document, not legal advice; have counsel review it for your jurisdiction.

| | |
| --- | --- |
| **Engagement ID** | [ACME-2026-11] |
| **Client** | [Legal name, address] |
| **Tester** | [Legal name, address] |
| **Document version** | [1.0, date] |

## 1. Purpose

[One or two sentences: what the client wants to learn. Example: "Find out what an outside attacker with no credentials can reach and misuse on the public systems of ACME Ltd."]

## 2. Test window

| | |
| --- | --- |
| **Starts** | [2026-11-20 09:00, UTC+03:00] |
| **Ends** | [2026-11-27 18:00, UTC+03:00] |
| **Allowed hours** | [Any time / weekdays 09:00–18:00 / outside business hours only] |
| **Blackout periods** | [Month-end closing, campaign days, none] |

Work outside this window is not authorized. An extension needs a new signed version of this document.

## 3. Scope

### In scope

| # | Asset | Type | Owner / hosting | Notes |
| --- | --- | --- | --- | --- |
| 1 | [example.com and subdomains] | Domain | [Client, own servers] | |
| 2 | [203.0.113.0/28] | Address range | [Client, data centre X] | |
| 3 | [app.example.com] | Web application | [Client] | [Test accounts provided: yes/no] |

### Out of scope

| Asset | Reason |
| --- | --- |
| [mail.example.com] | [Hosted by a third party that has not given permission] |
| [203.0.113.9] | [Production payment system] |

Assets hosted by third parties (cloud platforms, SaaS, CDN, payment providers) are **out of scope unless the third party's written permission is attached** to this document.

## 4. Proof of authorization

Before the window opens the client publishes this DNS TXT record on every domain listed as a proof domain:

```
name   _scopeguard.[example.com]
value  [output of `scopeguard record`]
```

The record shows that the client controls the domain and agreed to this engagement. **Removing the record withdraws the authorization immediately**; the tester's tooling refuses to continue.

## 5. Permitted activities

- [x] Discovery and enumeration of the assets in section 3
- [x] Vulnerability identification and manual verification
- [ ] Exploitation to demonstrate impact, limited to the minimum needed as evidence
- [ ] Authenticated testing with the accounts provided
- [ ] Password guessing against live accounts (rate: [max attempts per account per hour])
- [ ] Social engineering (scope: [who, which channels])
- [ ] Physical access testing

Anything not ticked is not permitted.

## 6. Prohibited activities

- Denial of service and any test meant to exhaust resources
- Changing, deleting or encrypting production data
- Accessing personal data beyond the minimum needed to prove the issue exists
- Moving from an in-scope system to an out-of-scope system, even if technically possible
- Leaving accounts, files or tools on client systems after the window
- [Add client-specific limits]

## 7. Handling of data and findings

- Evidence is stored encrypted and limited to what the report needs.
- Personal data seen during testing is neither copied nor kept; its exposure is reported as a finding.
- Credentials found during testing are reported to the client contact the same day and are not reused outside the scope.
- All engagement data is deleted [30] days after the final report, unless the client asks for earlier deletion in writing.
- Findings are confidential and shared only with the contacts in section 8.

## 8. Contacts

| Role | Name | Phone | E-mail | Hours |
| --- | --- | --- | --- | --- |
| Client lead | | | | |
| Client technical contact | | | | |
| Client emergency contact | | | | 24/7 |
| Tester lead | | | | |

## 9. Stop conditions

Testing stops at once and the client emergency contact is called when:

1. a system becomes slow or unavailable in a way that may be related to testing,
2. evidence of an earlier or ongoing compromise by someone else is found,
3. personal, financial or health data is exposed in bulk,
4. a critical finding puts the client at immediate risk,
5. the client asks, by any channel, or removes the DNS record in section 4.

Work resumes only after the client lead confirms in writing.

## 10. Deliverables

| Deliverable | Due |
| --- | --- |
| Same-day notice of critical findings | During testing |
| Report (see `report.md`) | [5] working days after the window |
| Walk-through meeting | [Date] |
| Retest of fixed findings | [Within 30 days of the fixes, once] |

## 11. Signatures

The client confirms that it owns or is entitled to authorize testing of every asset in section 3.

| | Client | Tester |
| --- | --- | --- |
| Name | | |
| Title | | |
| Date | | |
| Signature | | |
