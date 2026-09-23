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

There is a further problem of scope. The finding scored above is bounded to TLS 1.0, TLS 1.1 and CBC ciphersuites under TLS 1.2, because those are the configurations a scanner flags as deprecated, but [we have shown](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FHNDL-TLS-12-13.md) that TLS 1.2 with AEAD ciphersuites and TLS 1.3 are equally exposed to HNDL whenever the key exchange relies on a classical group rather than a post-quantum or hybrid mechanism. A vulnerability score attached to the deprecated configurations therefore draws a boundary in the wrong place: remediating everything it covers, by moving the estate to TLS 1.3 with a conventional key exchange, would close the finding entirely while leaving the harvesting risk untouched across a larger share of the traffic than the finding ever described.

The consequence is not that the 6.3 is wrong, but that it is answering a different question from the one an organisation handling long-lived secrets needs answered. A configuration can be simultaneously a Medium-severity vulnerability under CVSS and a severe unmitigated risk under an HNDL threat model, and an ISMS that records only the former has not documented the risk it actually carries.


### 2.1 Evaluation Method suggestion

The natural instinct at this point is to abandon CVSS and design a bespoke post-quantum risk framework. That would be a mistake for an organisation with an ISMS: CVSS scores are what feed the vulnerability register, the remediation SLAs, the board reporting and the auditor's sample, and a parallel scoring system that produces incomparable numbers will be quietly ignored within two review cycles. The method proposed here therefore keeps the CVSS v4.0 machinery entirely intact and adds a single, explicitly documented transformation on top of it. Every intermediate value is produced either by the official calculator or by arithmetic that a reviewer can reproduce on paper.

#### Step 1 : Score the harvesting attack as its own vector

Rather than distorting the deprecation vector, we build a second vector describing passive collection followed by retrospective decryption.

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Collection occurs on the network path |
| Attack Complexity | **Low** | Recording ciphertext requires no cryptanalytic technique, no race and no protocol trickery |
| Attack Requirements | Present | A collection position on the path is still required |
| Privileges Required | None | Passive capture requires no credentials |
| User Interaction | None | The victim is unaware and uninvolved |
| Confidentiality | **High** | Successful future decryption yields the entire session plaintext, not fragments |
| Integrity | None | Passive recording modifies nothing |
| Availability | None | The service is unaffected |
| Subsequent C / I / A | None | Scored conservatively; see note below |

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

Two parameters deserve a deliberate decision rather than a default. 
- **Attack Requirements** should be lowered to None where the traffic crosses international transit, a foreign jurisdiction, or any infrastructure on which bulk collection is a documented practice, since in those conditions the collection position is not a requirement the adversary must engineer but a standing property of the path.
- **Subsequent Confidentiality** should be raised to High where the harvested sessions are known to carry credentials, long-lived tokens or key material whose disclosure compromises systems beyond the TLS endpoint itself; it is left at None by default to avoid double-counting the same data under two metrics.

**Data sensitivity belongs in the Confidentiality Requirement** environmental metric, set to High for endpoints carrying regulated, personal or trade-secret data. This is native CVSS and keeps the sensitivity judgement inside the standard rather than inside our extension. The result of this step is a CVSS-BE score, written $S_{harv}$.

#### Step 2 : Refuse to apply Exploit Maturity

The Threat metric Exploit Maturity would be set to Unreported today, since no cryptanalytically relevant quantum computer is known to exist, and CVSS-BT would consequently reduce the score. This is precisely inverted for HNDL: the absence of a present-day decryption capability is the premise of the threat, not a mitigation of it. The method therefore mandates that Exploit Maturity remain Not Defined for HNDL assessments, and that the reason be recorded in the risk register entry so that a later reviewer does not "correct" the omission.

#### Step 3 : Derive the temporal exposure factor from Mosca's inequality

Three quantities must be estimated and recorded, all in years:

| Symbol | Quantity | Source of the estimate |
|---|---|---|
| $D_\ell$ | Confidentiality lifetime : how long the data must remain secret | Data retention schedule, regulatory minimum, contractual confidentiality term |
| $M_t$ | Migration time : time to deploy hybrid or post-quantum key exchange across the affected estate | Programme planning, dependency on vendor and library support |
| $Q_t$ | Quantum horizon : time until a cryptanalytically relevant quantum computer is assumed available | A single organisation-wide planning assumption, set by policy, not per-finding |

Mosca's inequality states that exposure exists whenever $D_\ell + M_t > Q_t$. We define the exposure gap and the temporal exposure factor as:

$$G = D_\ell + M_t - Q_t$$

$$T = \begin{cases} 0 & \text{if } G \leq 0 \\ \min\left(1, \dfrac{G}{Q_t}\right) & \text{if } G > 0 \end{cases}$$

The factor is zero exactly when Mosca's inequality is satisfied : the data will have ceased to be secret before any adversary can decrypt it, and there is genuinely no HNDL risk to record. Above that threshold it grows linearly in the gap, normalised by the quantum horizon so that the ratio expresses the shortfall as a proportion of the time available, and saturates at one when the gap equals or exceeds the horizon. Saturation matters: beyond that point the data is unambiguously exposed and further lengthening of the retention period does not make it more so.

Because $Q_t$ is an assumption rather than a measurement, the method requires the calculation to be repeated across the credible range — 10, 15 and 20 years is a reasonable default triple — and the **worst case retained**. A finding whose factor is zero at $Q_t = 20$ but non-zero at $Q_t = 10$ must be recorded as exposed, with the sensitivity noted.

#### Step 4 : Combine

$$S_{HNDL} = \max\left(S_{dep},\; T \times S_{harv}\right)$$

The maximum is used rather than a sum because both scores describe the same endpoint under two different threat models, and adding them would assert a compound severity that no single adversary realises. The endpoint's severity is the worse of the two readings of it. The composition also degrades correctly: when $T = 0$ the method returns the ordinary CVSS score unchanged, so applying it to an estate where HNDL is irrelevant costs nothing and changes no existing register entry.

The resulting figure is banded on the standard CVSS ranges (0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical), which is the property that keeps it comparable with every other finding in the register.

#### Step 5 : Record the derivation

The adjusted score is only defensible if its inputs travel with it. We propose a compact extension string appended to the CVSS vector in the register:

```
HNDL:1.0/DL:30/MT:4/QT:15/T:1.00/SH:8.7/SA:8.7
```

where `DL`, `MT` and `QT` are the three estimates in years, `T` the temporal factor to two decimals, `SH` the harvest vector's CVSS-BE score and `SA` the adjusted score. An auditor reading the register can recompute the entire chain from this string and the two CVSS vectors, which is what Annex A 8.8 asks for when it requires vulnerability assessments to be documented rather than merely performed.

#### Worked examples

| Endpoint | $D_\ell$ | $M_t$ | $Q_t$ | $G$ | $T$ | $S_{harv}$ | $S_{HNDL}$ |
|---|---|---|---|---|---|---|---|
| Public marketing site, no confidential payload | 0 | 3 | 15 | −12 | 0.00 | — | 6.3 Medium |
| Internal API, 7-year retention | 7 | 2 | 15 | −6 | 0.00 | 8.7 | 6.3 Medium |
| Patient records portal, lifetime confidentiality | 30 | 4 | 15 | +19 | 1.00 | 8.7 | 8.7 High |
| Legal document exchange, 20-year privilege | 20 | 3 | 15 | +8 | 0.53 | 8.7 | 6.3 Medium |

The behaviour is the one we want: the deprecation finding remains a Medium wherever the data is short-lived, and the same configuration escalates to High on the endpoint where confidentiality must survive the quantum horizon. The legal-exchange row is instructive — the gap is real but modest, the uplift is insufficient to overtake the deprecation score, and the register correctly shows a Medium with a documented HNDL exposure rather than a false escalation.

#### Limitations of the method

This is a heuristic, and it should be presented as one. The quantum horizon $Q_t$ is an assumption about which informed experts disagree by more than a decade, and every output inherits that uncertainty — which is why the method mandates a sensitivity range rather than a single figure. The linear form of $T$ and its normalisation by $Q_t$ are design choices selected for interpretability and correct behaviour at the boundaries, not results derived from data; no empirical calibration of HNDL outcomes exists, and none can exist until the threat materialises. And the use of $\max$ is a deliberate refusal to model compounding, which is conservative in one direction and arguably not conservative enough in another. What the method does provide is a reproducible, auditable number on the same scale as the rest of the vulnerability register, derived from stated assumptions that a reviewer can challenge individually — which is a materially better position than either ignoring HNDL or recording it as an unquantified narrative concern.

#### Practical implementation

[Here is an implementation](link) of the method as a static calculator. It takes the two CVSS v4.0 vectors described above, computes $S_{dep}$ and $S_{harv}$ with the official v4.0 scoring tables rather than an approximation, and applies the temporal factor and the $\max$ composition to produce $S_{HNDL}$ together with its severity band.


