# Deprecated TLS risk assessment and post-quantum risk assessment

## Deprecated/weak TLS in use : TLS 1.0, TLS 1.1, and TLS 1.2 with CBC ciphersuites

**[CVSS v4.0 vector:](https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N)** 
```
CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
```

**[CVSS v4.0 Score:](https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N)** 6.3 / Medium
```
Macro vector: 012201
Exploitability: High
Complexity: Medium
Vulnerable system: Low
Subsequent system: Low
Exploitation: High
Security requirements: Medium
```

**Base Metrics**

| Metric | Selected value | Rationale |
|---|---|---|
| Attack Vector | Network  | Attacker reaches the TLS listener remotely |
| Attack Complexity  | High  | Requires defeating the crypto (padding-oracle / BEAST / Lucky13-style work), not a straight request |
| Attack Requirements  | Present  | Needs an on-path/MITM position plus repeated victim traffic |
| Privileges Required  | None | No account needed |
| User Interaction  | None | No victim click required |
| Confidentiality  | Low | Partial plaintext recovery, not the whole session |
| Integrity  | Low | Limited ciphertext manipulation possible |
| Availability  | None | Service stays up |
| Subsequent Confidentiality / Integrity / Availability  | None | No impact beyond the TLS endpoint |

**Supplemental Metrics**

| Metric | Selected value | Rationale |
|---|---|---|
| Safety | Not Defined  | No safety dimension for a web/TLS endpoint |
| Automatable  | Not Defined | Leave undefined; set to No only if your policy requires a value, since the MITM step is not automatable at scale |
| Recovery | Not Defined | No availability impact to recover from |
| Value Density | Not Defined | Depends on the specific asset |
| Vulnerability Response Effort | Not Defined | Optional; remediation is a config change, so Low is defensible |
| Provider Urgency | Not Defined | No vendor-supplied urgency rating |

**Environmental:** The following metrics are set as Not Defined, because there is no environment-specific override:
- Attack Vector / Complexity / Requirements,
- Privileges Required, User Interaction,
- Confidentiality, Integrity, Availability,
- Subsequent Confidentiality / Integrity / Availability.

**Environmental:** The following metrics are set as Not Defined:
- Confidentiality Requirement ; Raise to High only if the endpoint carries regulated or sensitive data,
- Integrity / Availability Requirement ; Raise only if tailoring to a specific asset

Changing these metrics however, does not affect the overall score.

**Threat Metrics:** The Exploit Maturity is set to Not Defined because public PoCs exist, so POC is defensible if your policy uses threat metrics; leaving it undefined keeps the CVSS-B score.


## TLS with non HNDL-safe encryption schemes


