# Deprecated TLS risk assessment and post-quantum risk assessment

## 1. Deprecated/weak TLS in use : TLS 1.0, TLS 1.1, and TLS 1.2 with CBC ciphersuites

We have shown in [Breaking TLS 1.2 CBC mode, TLS 1.1, and TLS 1.0](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FTLS-12CBC-11-10.md) that TLS 1.0, TLS 1.1 and the CBC ciphersuites still permitted under TLS 1.2 are deprecated. Deprecation, however, is a statement about standards rather than about exposure: [RFC 8996](https://www.rfc-editor.org/info/rfc8996/) formally prohibits the negotiation of TLS 1.0 and 1.1, and [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) requires TLS 1.2 as a minimum with TLS 1.3 preferred, but neither document tells an operator how much damage the continued presence of these protocols would actually do to a given service. That gap between "non-compliant" and "dangerous" is what this section sets out to close.

The distinction matters for an [ISMS](https://en.wikipedia.org/wiki/Information_security_management). [ISO/IEC 27001](https://www.iso.org/standard/27001) does not ask an organisation to eliminate every deviation from a standard; it asks for identified risks to be assessed against defined criteria and then treated, accepted, transferred or avoided through a documented decision. Annex A control 8.24 governs the use of cryptography and the rules for key and algorithm selection, while 8.8 covers the management of technical vulnerabilities, and both are satisfied by a reasoned, recorded judgement rather than by unconditional removal. A finding of "deprecated protocol enabled" therefore has to be converted into something the risk owner can weigh against the cost and breakage of disabling it, which in practice means a severity score, an exploitability argument, and an explicit statement of what the score does not capture.

Two regimes narrow that discretion. [PCI DSS v4.0](https://www.pcisecuritystandards.org/standards/pci-dss/) treats TLS 1.0 and 1.1 as unacceptable for the protection of cardholder data outright, and the ANSSI cryptographic guidance likewise rules out the affected constructions for systems under its scope, so for in-scope assets the decision is a compliance obligation rather than a risk trade-off. Everywhere else, the assessment below applies.

### 1.1 The CVSS score

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

### 1.2 Limitations

The score above is a useful summary, but it is worth being explicit about what a CVSS v4.0 figure of 6.3 does and does not represent before it is carried into a treatment decision.

- **CVSS measures severity, not risk.** The Base score is an intrinsic property of the weakness, deliberately independent of how exposed the affected endpoint is, how valuable the data traversing it is, how many attackers are positioned to reach it, or how likely exploitation actually is. Risk requires likelihood multiplied by consequence in a specific context.
- **The scale is ordinal, not arithmetic.** A 6 is not twice as bad as a 3 ! And the difference between 6.3 and 6.8 is not meaningfully interpretable.

**Most importantly for what follows, the model assumes impact is contemporaneous with exploitation.** Every CVSS metric describes what an attacker achieves at the moment of the attack, with the implicit premise that the capability required is available now. That premise fails for an emerging class of threat that the remainder of this assessment addresses: [Harvest Now, Decrypt Later](https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later).


## 2. TLS with non HNDL-safe encryption schemes

HNDL is poorly served by the score for three specific reasons. 
- The Attack Complexity of High and Attack Requirements of Present, which together hold the present score down, reflect the difficulty of an active on-path attack. But harvesting requires only passive capture, which is cheap, undetectable, silent, and already within the means of a well-resourced adversary.
- The Confidentiality impact of Low reflects partial plaintext recovery under an oracle attack, whereas a successful future decryption of a harvested session yields the entire plaintext.
- And the temporal structure of the threat is simply absent: the relevant question is whether the confidentiality lifetime of the data plus the time required to migrate exceeds the time until a capable quantum adversary appears ([Mosca's inequality](https://utimaco.com/service/knowledge-base/post-quantum-cryptography/what-mosca-theorem)) and CVSS has no metric in which that comparison can be expressed.

The consequence is not that the 6.3 is wrong, but that it is answering a different question from the one an organisation handling long-lived secrets needs answered. A configuration can be simultaneously a Medium-severity vulnerability under CVSS and a severe unmitigated risk under an HNDL threat model, and an ISMS that records only the former has not documented the risk it actually carries. 

### 2.1 Evaluation Method suggestion


