# Web application checklist

Organised by the categories of the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) so each finding can cite its test case. It lists what to verify, not how to attack; the guide has the technique for every line.

Use two test accounts per role where the rules of engagement allow it. Most authorization problems only show when one account asks for the other's data.

| Done | Category | Verify |
| --- | --- | --- |
| ☐ | **Information gathering** (WSTG-INFO) | Entry points, parameters and roles are mapped; framework and server versions noted; nothing sensitive in page source, comments or metadata files |
| ☐ | **Configuration** (WSTG-CONF) | No default or sample content; administrative interfaces not public; security headers present; HTTPS enforced everywhere; backups and old files not reachable; error pages reveal nothing |
| ☐ | **Identity management** (WSTG-IDNT) | Registration cannot create privileged accounts; the application does not reveal which user names exist; account recovery cannot be used to take over someone else's account |
| ☐ | **Authentication** (WSTG-ATHN) | No default credentials; lockout or throttling works; second factor cannot be skipped; password reset links are single-use, short-lived and unguessable; "remember me" is safe |
| ☐ | **Authorization** (WSTG-ATHZ) | A user cannot read or change another user's records by changing an identifier; a lower role cannot call a higher role's functions; rules are enforced on the server, not only hidden in the interface |
| ☐ | **Session management** (WSTG-SESS) | Session identifier changes at login and dies at logout; cookies carry the right flags; state-changing requests are protected against cross-site request forgery; idle and absolute time-outs exist |
| ☐ | **Input validation** (WSTG-INPV) | Every input that reaches a database, a shell, a file path, a template or another server is handled safely; output is encoded for where it lands; file uploads cannot place executable content |
| ☐ | **Error handling** (WSTG-ERRH) | Errors show no stack traces, queries or internal paths; unexpected input fails closed |
| ☐ | **Cryptography** (WSTG-CRYP) | No secrets in the client or the repository; current transport encryption; passwords stored with a slow salted hash; tokens are random, not derived from guessable values |
| ☐ | **Business logic** (WSTG-BUSL) | Steps cannot be skipped or repeated for gain; prices, quantities and limits are checked on the server; two simultaneous requests cannot spend the same balance twice |
| ☐ | **Client side** (WSTG-CLNT) | Script cannot be injected through the page itself; redirects only go to expected places; cross-origin rules are not wide open; nothing sensitive in browser storage |
| ☐ | **APIs** (WSTG-APIT) | Every endpoint enforces authentication and object-level authorization on its own; responses do not return more fields than the screen shows; undocumented and old versions are not left running |

## For every finding

- Reproduced a second time, from a clean session
- Evidence captured with personal data and secrets redacted
- The fix is specific enough for a developer to start on
- The same pattern looked for elsewhere in the application
- Written up with `templates/finding.md`
