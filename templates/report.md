# Penetration Test Report

> Skeleton. Replace the brackets, delete the notes in quote blocks. Sections 1 and 2 are for management and must stand on their own; a reader who stops after page two should still know what to do on Monday.

| | |
| --- | --- |
| **Client** | [ACME Ltd.] |
| **Engagement ID** | [ACME-2026-11] |
| **Test window** | [2026-11-20 09:00 to 2026-11-27 18:00, UTC+03:00] |
| **Report version** | [1.0, 2026-12-02] |
| **Author** | [Name, contact] |
| **Classification** | Confidential: for the named client contacts only |

## 1. Summary for management

**Overall risk: [High]**

[Three to five sentences, no jargon. What was tested, the single most important result, what it means for the business, what to do first.]

| Severity | Count | Fixed during the test |
| --- | --- | --- |
| Critical | [0] | |
| High | [2] | |
| Medium | [4] | |
| Low | [3] | |
| Informational | [5] | |

### The three things to do first

1. [Action, owner, why. One line each.]
2.
3.

### What worked well

> Keep this honest and specific. A client that only ever hears bad news stops listening.

- [Example: Administrative interfaces were reachable only through the VPN.]

## 2. Findings at a glance

| ID | Finding | Severity | Asset | Status |
| --- | --- | --- | --- | --- |
| F-01 | [Order details of other customers readable by changing the order number] | High | app.example.com | Open |
| F-02 | | | | |

## 3. Scope and authorization

| | |
| --- | --- |
| **Rules of engagement** | [Version 1.0, signed 2026-11-18] |
| **In scope** | [example.com and subdomains; 203.0.113.0/28] |
| **Out of scope** | [mail.example.com (third party); 203.0.113.9 (payment system)] |
| **Approach** | [No prior knowledge / test accounts provided / source code provided] |
| **Authorization record** | `_scopeguard.[example.com]`, verified before every tool run |
| **Limits that affected the result** | [Example: testing allowed only outside business hours; no load testing] |

> State what was *not* tested and why. An untested area is not a clean area.

## 4. Method

Testing followed these stages; the checklists used are attached.

| Stage | What was done |
| --- | --- |
| Reconnaissance | [Public sources only: DNS, certificate logs, published documents] |
| Mapping | [Service and application discovery on in-scope assets] |
| Analysis | [Manual review of authentication, authorization, input handling, configuration] |
| Verification | [Each finding confirmed by hand; impact shown with the minimum needed] |
| Reporting | [Critical findings reported the same day; this report] |

**Severity** follows CVSS v3.1 base scores, adjusted where the business context clearly changes the risk (the adjustment is explained in the finding).

| Severity | CVSS | Expected response |
| --- | --- | --- |
| Critical | 9.0–10.0 | Fix or mitigate immediately |
| High | 7.0–8.9 | Fix within [14] days |
| Medium | 4.0–6.9 | Fix within [60] days |
| Low | 0.1–3.9 | Fix in normal maintenance |
| Informational | – | Improvement, no direct risk |

## 5. Findings in detail

> One section per finding, using `finding.md`. Order by severity.

### F-01 …

## 6. Remediation plan

| Priority | Action | Findings covered | Suggested owner | Effort |
| --- | --- | --- | --- | --- |
| 1 | [Add ownership check to all object endpoints] | F-01, F-04 | [Backend team] | [Days] |
| 2 | | | | |

A retest of the fixed findings is included [once, within 30 days of the fixes].

## Appendix A. Test log

> Export of `scopeguard.log` for the engagement: what was run, against which target, when (UTC). Attach the file; show the first and last entries here.

| First entry | Last entry | Runs | Refused |
| --- | --- | --- | --- |
| [2026-11-20T06:02:11Z] | [2026-11-27T14:48:40Z] | [312] | [7] |

## Appendix B. Tools

| Tool | Version | Used for |
| --- | --- | --- |
| | | |

## Appendix C. Cleanup

| Item | Created | Removed |
| --- | --- | --- |
| [Test account pentest-a@example.com] | [2026-11-20] | [2026-11-27, confirmed by client] |

All engagement data held by the tester will be deleted on [date].
