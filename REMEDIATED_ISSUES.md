# 🛡️ Security & Tech-Debt Remediation — Apache Superset (fork)

Issues surfaced by an autonomous **Devin code scan**, filed as GitHub issues, remediated by **Devin sessions**, then **independently reviewed** by a separate Devin session (with a bounded **autofix loop**) before merge.

> Orchestrated by the [Devin Remediation Console](https://github.com/louisgrimaldi/devin-remediation-console) — scan → file → remediate → review → autofix → merge, on the Devin API.

**13 issues tackled** · 5 High · 5 Medium · 3 Low · **12 merged**.

| # | Title | Severity | Category | Status | Issue | PR |
|---|-------|----------|----------|--------|-------|----|
| 15 | Insecure MD5/SHA-1 hash functions used | 🔴 High | Security | ✅ Merged | [#15](https://github.com/louisgrimaldi/superset/issues/15) | [#22](https://github.com/louisgrimaldi/superset/pull/22) |
| 25 | Pillow 12.2.0 has 5 known CVEs including shell command injection | 🔴 High | Dependency | ✅ Merged | [#25](https://github.com/louisgrimaldi/superset/issues/25) | [#26](https://github.com/louisgrimaldi/superset/pull/26) |
| 27 | Vulnerable paramiko 3.5.1 (no fixed release yet) | 🔴 High | Dependency | ✅ Merged | [#27](https://github.com/louisgrimaldi/superset/issues/27) | [#28](https://github.com/louisgrimaldi/superset/pull/28) |
| 29 | subprocess invoked with shell=True | 🔴 High | Security | ✅ Merged | [#29](https://github.com/louisgrimaldi/superset/issues/29) | [#40](https://github.com/louisgrimaldi/superset/pull/40) |
| 30 | Jinja2 Environment created with autoescape disabled | 🔴 High | Security | ✅ Merged | [#30](https://github.com/louisgrimaldi/superset/issues/30) | [#35](https://github.com/louisgrimaldi/superset/pull/35) |
| 16 | Dynamic exec() of compiled source | 🟠 Medium | Security | ✅ Merged | [#16](https://github.com/louisgrimaldi/superset/issues/16) | [#21](https://github.com/louisgrimaldi/superset/pull/21) |
| 17 | yaml.load used with unsafe Loader | 🟠 Medium | Security | ✅ Merged | [#17](https://github.com/louisgrimaldi/superset/issues/17) | [#24](https://github.com/louisgrimaldi/superset/pull/24) |
| 18 | SQL built via string interpolation (injection risk) | 🟠 Medium | Security | ✅ Merged | [#18](https://github.com/louisgrimaldi/superset/issues/18) | [#23](https://github.com/louisgrimaldi/superset/pull/23) |
| 31 | markupsafe.Markup on dynamic content (XSS) | 🟠 Medium | Security | ✅ Merged | [#31](https://github.com/louisgrimaldi/superset/issues/31) | [#39](https://github.com/louisgrimaldi/superset/pull/39) |
| 32 | Binding to all network interfaces (0.0.0.0) | 🟠 Medium | Security | ✅ Merged | [#32](https://github.com/louisgrimaldi/superset/issues/32) | [#36](https://github.com/louisgrimaldi/superset/pull/36) |
| 19 | HTTP request issued without a timeout | ⚪ Low | Security | ✅ Merged | [#19](https://github.com/louisgrimaldi/superset/issues/19) | [#20](https://github.com/louisgrimaldi/superset/pull/20) |
| 33 | Silent try/except/pass swallowing exceptions | ⚪ Low | Code quality | 🔵 In review | [#33](https://github.com/louisgrimaldi/superset/issues/33) | [#38](https://github.com/louisgrimaldi/superset/pull/38) |
| 34 | Unused imports, redefinitions and shadowed names | ⚪ Low | Lint | ✅ Merged | [#34](https://github.com/louisgrimaldi/superset/issues/34) | [#37](https://github.com/louisgrimaldi/superset/pull/37) |

---

_Generated from the console's state store; status reflects the live remediate → review → autofix → merge pipeline._
