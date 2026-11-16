# [F-01] [Short title that names the problem and the place]

> One file per finding. A good title can be read alone: "Order details of other customers readable by changing the order number", not "IDOR".

| | |
| --- | --- |
| **Severity** | [Critical / High / Medium / Low / Informational] |
| **CVSS v3.1** | [8.1] `[CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N]` |
| **Affected asset** | [https://app.example.com/orders/{id}] |
| **Category** | [CWE-639 Authorization Bypass Through User-Controlled Key] |
| **Personal data involved** | [Yes: names, addresses / No] |
| **Found on** | [2026-11-22] |
| **Status** | [Open / Fixed, retest pending / Fixed and verified on 2026-12-10 / Risk accepted by …] |

## What is wrong

[Two to four sentences in plain language. What the system does, what it should do instead.]

## Why it matters

[The consequence for the business, in the client's terms: who can do what to whom, at what scale, with what effort. Avoid "an attacker could potentially".]

## Evidence

Steps to reproduce, short enough that the client's developer can repeat them in five minutes:

1. [Sign in as test user A.]
2. [Open `/orders/1042`, which belongs to user A.]
3. [Change the number to `1043`. The order of user B is shown.]

```http
GET /orders/1043 HTTP/1.1
Host: app.example.com
Cookie: session=[redacted]

HTTP/1.1 200 OK
{"customer": "[redacted]", "address": "[redacted]", ...}
```

[Screenshot or log excerpt. Redact personal data and secrets; show only enough to prove the point.]

Tool run recorded in the audit log: `[2026-11-22T09:14:03Z, scopeguard.log line 12]`

## How to fix it

**Fix:** [The specific change. "Check on the server that the order belongs to the signed-in customer before returning it."]

**Also check:** [Other places with the same pattern: invoices, addresses, support tickets.]

**Short-term mitigation, if the fix takes time:** [Rate limiting, monitoring rule, feature switch.]

## References

- [OWASP WSTG-ATHZ-04: Testing for Insecure Direct Object References]
- [Vendor documentation, CVE, internal standard]

## Retest

| Date | Result | Notes |
| --- | --- | --- |
| | | |
