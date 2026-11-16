# External attack surface checklist

What an outsider can see and reach. Passive steps come first because they send nothing to the client's systems and often change what is worth testing. Keep the evidence named in the last column; it goes straight into the report.

Before anything else: `scopeguard status` shows an open window and a valid record.

## 1. Know what you are looking at (passive)

| # | Check | Evidence to keep |
| --- | --- | --- |
| 1.1 | List every domain and subdomain from public sources: DNS records, certificate transparency logs, search engines, public code | The list, with the source of each name |
| 1.2 | For each name, find who actually hosts it: the client, a cloud provider, a SaaS platform, a CDN | Name → address → network owner table |
| 1.3 | Mark third-party hosting as **out of scope** unless that party's permission is attached to the rules of engagement; add `resolves_within` to the scope file where it helps | Updated scope file |
| 1.4 | Compare the list with the signed scope and ask the client about every name they did not mention | The client's written answer |
| 1.5 | Look for names that point at resources that no longer exist (released cloud addresses, deleted hosted pages) | Name, target, why it is dangling |

> Step 1.4 regularly produces the most valuable finding of the whole test: systems the client forgot they had.

## 2. What the client publishes about itself (passive)

| # | Check | Evidence to keep |
| --- | --- | --- |
| 2.1 | Mail protection records: SPF, DKIM, DMARC present and enforcing | The records as published |
| 2.2 | Credentials, keys or internal host names in public code repositories and paste sites | Link, date, what was exposed (redacted) |
| 2.3 | Internal details in published documents: user names, software versions, paths | Document and field |
| 2.4 | Open cloud storage that carries the client's name | Location and a listing, not the contents |
| 2.5 | Leaked account lists that include the client's mail domain | Count and source only; never test the passwords without explicit permission |

## 3. What answers from the outside (active, in scope only)

Every command in this section goes through `scopeguard run`.

| # | Check | Evidence to keep |
| --- | --- | --- |
| 3.1 | Which ports answer on each in-scope address; which service and version sits behind each | Scan output with time stamps |
| 3.2 | Services that should never face the internet: remote administration, databases, file sharing, management interfaces | Address, port, banner |
| 3.3 | Software with known vulnerabilities for the version it reports; confirm by hand before reporting | Version evidence and the advisory |
| 3.4 | Login pages: default credentials, missing lockout, no second factor on administrative access | Screenshot; attempts within the agreed limits |
| 3.5 | Transport encryption: expired or mismatched certificates, obsolete protocol versions, weak configuration | Tool output |
| 3.6 | Forgotten content: test and staging sites, backups, version control folders, default pages, exposed configuration | Address and a short excerpt |
| 3.7 | Remote access (VPN, remote desktop gateways): exposure, patch level, authentication strength | Banner and configuration evidence |

## 4. Before you leave

| # | Check |
| --- | --- |
| 4.1 | Every finding verified by hand, not only reported by a scanner |
| 4.2 | Critical findings already reported to the client contact |
| 4.3 | Nothing left behind on client systems; cleanup table in the report filled in |
| 4.4 | `scopeguard.log` exported for the report appendix |
| 4.5 | Areas you could not test written down, with the reason |
