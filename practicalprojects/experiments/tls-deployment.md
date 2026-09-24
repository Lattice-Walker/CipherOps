# TLS in Practice: A Sector-by-Sector Survey of Present and Post-Quantum Risk

## i. The deprecated TLS protocols

We have shown in [Breaking TLS 1.2 CBC mode, TLS 1.1, and TLS 1.0](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FTLS-12CBC-11-10.md) that TLS 1.2 CBC mode, TLS 1.1, and TLS 1.0 are deprecated. The failures are structural. CBC mode in TLS inherits a MAC-then-encrypt construction whose padding check leaks through timing, and TLS 1.0 and 1.1 additionally depend on hash and PRF constructions that no longer meet any current standard. None of these weaknesses can be repaired within the protocol version that exhibits them, so the only remedy is migration to a later version.

We have also shown in [Deprecated TLS risk assessment and post-quantum risk assessment](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fgovernance%2FTLS-risk-assessment.md) that these protocols carry a CVSS v4.0 score of 6.3 (Medium). Deprecation applies to a protocol specification and says nothing about the state of a fleet. A server remains reachable over TLS 1.0 until an administrator changes its configuration, whatever the specification says. The present study measures this gap, which reduces to two questions that are easy to conflate. The first is what a server negotiates by default, which describes the protection a normal visitor receives. The second is what a server accepts, which describes the protection available to an attacker who may propose anything the server tolerates. A host that defaults to TLS 1.3 but still accepts TLS 1.0 gives its users the first answer and its adversaries the second, and only the second bounds the risk. We therefore report both throughout.

## ii. TLS 1.2 AEAD mode and TLS 1.3

We have shown in [The Security of TLS 1.2 AEAD mode and TLS 1.3](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FTLS-12AEAD-13.md) that TLS 1.2 AEAD mode and TLS 1.3 are cryptographically secure. Against any adversary bounded by classical computation, the guarantees hold. Authenticated encryption closes the padding-oracle class of attacks, and ephemeral key exchange provides forward secrecy, so compromising a server's long-term key tomorrow does not open the sessions it completed today. A host in this configuration is secure against the adversary the protocols were designed for.

The key exchange in these configurations is classical (ECDHE over X25519 or a NIST curve), and its security rests on a discrete logarithm problem that Shor's algorithm solves. An adversary who records a handshake today and obtains a cryptographically relevant quantum computer at any point within the confidentiality lifetime of that traffic recovers the session key and decrypts the session. This is the harvest-now-decrypt-later (HNDL) problem. We have shown in [Deprecated TLS risk assessment and post-quantum risk assessment](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fgovernance%2FTLS-risk-assessment.md) that TLS 1.2 AEAD mode and TLS 1.3 lack HNDL security. Under the [HNDL safety scoring method](https://lattice-walker.github.io/CipherOps/display_practicalprojects/practicalprojects.html#article=practicalprojects%2FTools%2FHNDL-CVSS-calculator.md) we established, they receive an SHNDL score of 8.2 (High).

The CVSS v4.0 score of 6.3 and the SHNDL score of 8.2 belong to different scales, so the higher number does not make the modern protocols worse than the deprecated ones. CVSS measures what an adversary can do now, and SHNDL measures what a recorded session is worth later. The pairing shows that a fleet can be migrated off every deprecated protocol and score well on present-day assessments while remaining fully exposed on the forward-looking one. Security in this setting has more than one axis, and a survey that measured only deprecation would report such a fleet as healthy.

The measurements that follow therefore treat TLS 1.2 AEAD mode and TLS 1.3 separately from TLS 1.3 paired with a post-quantum key exchange, and do not group them as "modern TLS". The distinction depends on the hard problem that the session key ultimately rests on, and only this distinction determines whether traffic captured today remains confidential.

## iii. TLS 1.3 paired with ML-KEM

We have shown in [The post quantum security of TLS 1.3 ML KEM](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FHNDL-TLS-12-13.md) that TLS 1.3 paired with ML-KEM is HNDL safe. The deployed form is a hybrid group (X25519MLKEM768) in which the client offers a single key share carrying both an X25519 public key and an ML-KEM-768 encapsulation key, and the session secret is derived from both results together. The derived key remains secure as long as either component is secure. A cryptanalytic break of ML-KEM leaves the classical X25519 exchange intact, and a quantum adversary who solves the discrete logarithm still faces the lattice problem.

The handshake authenticates the server as well as exchanging keys, and the certificate chain in these connections remains classical RSA or ECDSA. Authentication is a claim about the present: the signature proves the server's identity at the moment of the handshake. An adversary who acquires the ability to forge that signature in ten years can impersonate the server in ten years but cannot decrypt a session that has already completed. Confidentiality, by contrast, can be attacked retroactively, and the key exchange determines it. Post-quantum authentication is a separate problem. It does not belong to the harvest-now-decrypt-later problem, and this survey does not measure it.

## 1. The banking sector

Of the 92 reachable banking domains, none uses a deprecated protocol by default. 63.0% use TLS 1.3, 18.5% use TLS 1.3 with ML-KEM, and 18.5% use TLS 1.2 in AEAD mode. Every ordinary visitor therefore receives a protocol that section ii shows to be cryptographically secure. For 81.5% of the domains, however, that protocol also carries an SHNDL score of 8.2 (High). The sector is in good shape against today's attacker and exposed against tomorrow's.

![Banking sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Banques_tls_default_protocols.svg)

Two points about the supported-protocols figure apply to all five sectors. First, the filled part of the TLS 1.3 column is made up of the hosts that use TLS 1.3 with a post-quantum group, which are counted again in the TLS 1.3 PQ column. It does not represent hosts that refuse TLS 1.3. Second, the TLS 1.3 PQ column is completely unfilled in every sector, because support and default are identical there. This is an artefact of the measurement and does not describe the deployments. The scan reads the key exchange group from one completed handshake, so a server that supports a hybrid group but prefers X25519 is indistinguishable from a server that supports none. Every post-quantum figure here is therefore a lower bound on server capability and an exact measure of what connections actually receive.

The accepted-protocol results are weaker for banking. No host prefers a deprecated protocol, yet 70.7% still accept TLS 1.2 in CBC mode, the highest rate in the survey. Only 29.3% of banking domains accept no deprecated protocol at all. As section i establishes, risk is set by what a server accepts and not by what it prefers, so the CVSS v4.0 score of 6.3 (Medium) applies to more than two thirds of the sector. Banking is also the only sector with no TLS 1.0 or TLS 1.1 anywhere. The minimum version was raised deliberately, but the cipher list was not updated with it.

![Banking sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Banques_tls_supported_protocols.svg)

Eleven of the 103 banking domains scanned did not complete a handshake. All eleven were stopped by bot-blocking defences: six connections were dropped silently after the ClientHello, and five were reset immediately after it. Both patterns are consistent with a web application firewall or an anti-bot system. These are security measures, and they affect how the figures should be read. A domain that refuses automated probes is likely better maintained than one that answers any request, so the excluded hosts are not a random sample. Every figure in this survey describes the domains that allowed measurement, which may be slightly weaker than the sector as a whole. The effect is largest in banking, the only sector in which every exclusion came from such a defence.

## 2. The energy sector

The energy sector has the best post-quantum result in the survey and one of the worst legacy results, both within the same population. Of 107 reachable domains, 43.0% use TLS 1.3 with ML-KEM by default, 41.1% use TLS 1.3 with a classical group, and 15.9% use TLS 1.2 in AEAD mode. Almost half of all connections to this sector are HNDL safe as defined in section iii, against 14.9% in the government sector. The other 57.0% carry the 8.2 (High) exposure.

![Energy sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Energie_tls_default_protocols.svg)

Post-quantum progress has not been accompanied by legacy removal. TLS 1.0 and TLS 1.1 are accepted by 10.3% of energy domains, the highest rate in the survey, and TLS 1.2 in CBC mode by 59.8%. Only 40.2% accept no deprecated protocol. These groups overlap: 28.0% of all energy domains both use a post-quantum key exchange by default and accept at least one deprecated protocol. Just over a quarter of the sector is protected against an attacker who does not yet exist and open to one who does.

This supports the argument in section ii. The two risks move independently, and progress on one says nothing about the other. Enabling a hybrid key exchange requires recent software, so these operators have updated their TLS stack, but they have not revised the list of ciphers they accept. Energy is the clearest example in the survey of post-quantum migration and present-day configuration hygiene being separate tasks.

![Energy sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Energie_tls_supported_protocols.svg)

Twenty-two of the 129 energy domains scanned did not complete a handshake. That is 17.1%, the highest rate of the five sectors. Eighteen of them were stopped by bot-blocking defences, twelve by a silent drop after the ClientHello and six by an immediate reset. The other four failed for unrelated reasons. The selection effect described in section 1 applies here more than in any other sector except banking.

## 3. The defense sector

Of 85 reachable defense domains, 64.7% use TLS 1.3 by default, 20.0% use TLS 1.3 with ML-KEM, and 15.3% use TLS 1.2 in AEAD mode. No host prefers a deprecated protocol. The post-quantum share of 20.0% places the sector in the middle of the survey, below energy at 43.0% and medical at 31.9%, and above government at 14.9%. Four connections in five remain in the 8.2 (High) band.

![Defense sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Defense_tls_default_protocols.svg)

Defense has the best legacy result of the four non-governmental sectors. TLS 1.0 and TLS 1.1 are accepted by 8.2% of domains and TLS 1.2 in CBC mode by 44.7%, against 70.7% for banking and 59.8% for energy. A majority of the sector, 55.3%, accepts no deprecated protocol at all, and only government does better. Support for TLS 1.2 in AEAD mode is 97.6% and for TLS 1.3 is 84.7%, both in line with the rest of the survey.

The following point comes from reasoning and not from the scan. Harvest-now-decrypt-later risk depends on how long the recorded traffic stays valuable, and defense traffic plausibly stays valuable longer than any other traffic measured here. A recording that matters for twenty or thirty years is exposed to any quantum capability that arrives within that window, whereas a recording that matters for eighteen months is not. A post-quantum share of 20.0% therefore leaves more real risk in this sector than the same figure would elsewhere, even though the figure itself is unremarkable.

![Defense sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Defense_tls_supported_protocols.svg)

Fifteen of the 100 defense domains scanned did not complete a handshake. Thirteen were stopped by bot-blocking defences, twelve by a silent drop after the ClientHello and one by an immediate reset, and two returned a TLS alert. The exclusion is not random, for the reason given in section 1.

## 4. The medical sector

The medical sector has the highest modern-protocol support in the survey and a strong post-quantum share. Of 119 reachable domains, 59.7% use TLS 1.3 by default, 31.9% use TLS 1.3 with ML-KEM, 7.6% use TLS 1.2 in AEAD mode, and 0.8%, a single host, uses TLS 1.2 in CBC mode. Support for TLS 1.2 in AEAD mode reaches 99.2% and for TLS 1.3 reaches 91.6%, both the highest recorded. The post-quantum share of 31.9% is second only to energy.

![Medical sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Hopitaux_tls_default_protocols.svg)

The single host that uses TLS 1.2 in CBC mode is better treated as an individual finding than as a statistic. Section i shows that this configuration carries a CVSS v4.0 score of 6.3 (Medium) against an attacker who needs no future capability. The host does not merely tolerate the configuration on request. It directs ordinary visitors into it. Given the kind of data that medical infrastructure handles, a weakness usable today is a different problem from one usable later, and this host should be fixed immediately.

The accepted-protocol results weaken the sector's otherwise strong position. TLS 1.2 in CBC mode is accepted by 58.0% of medical domains and TLS 1.0 and TLS 1.1 by 7.6%, leaving 42.0% that accept no deprecated protocol. As in energy, the two groups overlap heavily: 27.7% of all medical domains both use a post-quantum key exchange by default and accept at least one deprecated protocol. The sector leads on modern protocol support, ranks second on post-quantum adoption, and sits near the survey median on legacy exposure.

![Medical sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Hopitaux_tls_supported_protocols.svg)

Thirteen of the 132 medical domains scanned did not complete a handshake. Eleven were stopped by bot-blocking defences and two failed for reasons that could not be determined. The selection effect from section 1 applies, so the figures reported here may slightly understate the sector's true position.

## 5. The governmental sector

The governmental sector is the largest sample in the survey, with 1251 reachable domains. That is roughly three times the other four sectors combined, so its figures are the most stable. 71.1% use TLS 1.3 by default, 14.9% use TLS 1.3 with ML-KEM, 13.8% use TLS 1.2 in AEAD mode, and 0.2%, two hosts, use TLS 1.2 in CBC mode.

![Governmental sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Gouv_tls_default_protocols.svg)

Against today's attacker this sector performs best of the five. TLS 1.2 in CBC mode is accepted by 31.3% of domains, against 70.7% for banking and 58.0% for medical, and 68.7% accept no deprecated protocol at all. Support for TLS 1.3 reaches 86.0%. TLS 1.1 is accepted by 7.8% of domains and TLS 1.0 by 7.0%, so a small group of hosts has removed the older version while keeping the newer one. Legacy cleanup in these hosts is partial. The two hosts that default to CBC mode are individual findings of the same kind as the one in the medical sector and need the same treatment.

Against tomorrow's attacker the order reverses completely. At 14.9%, government has the lowest post-quantum share in the survey, less than half the medical figure and about a third of the energy figure. So 85.1% of all connections to French governmental domains carry the 8.2 (High) exposure described in section ii, and this sector also contributes the largest number of domains in the survey. The sector that has gone furthest in retiring protocols that today's attackers can break has gone least far in adopting the key exchange that stops tomorrow's.

This reversal is the central finding of the survey. Energy has the highest post-quantum share and one of the weakest legacy results, the reverse of government, and the two sectors together show that the five sectors cannot be placed in a single order of TLS quality. Removing deprecated protocols and adopting post-quantum key exchange are separate pieces of work, and operators are evidently doing them at different rates. An assessment that reported only one of the two would rank these sectors in roughly the wrong order.

![Governmental sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Gouv_tls_supported_protocols.svg)

Forty-three of the 1294 governmental domains scanned did not complete a handshake. That is 3.3%, by far the lowest rate in the survey. Forty-two of the forty-three were stopped by silent filtering of the ClientHello, which is consistent with a web application firewall. The low rate is informative in itself: governmental domains are much less likely than banking or energy domains to place bot-blocking defences in front of their public services. The selection effect from section 1 therefore affects this sector least, and on that count as well as on sample size its figures are the most representative in the survey.

## iv. Recommendations

We recommend one of two configurations: TLS 1.3 with a classical key exchange, or TLS 1.3 paired with ML-KEM. The choice depends on how long the data carried by the website must remain confidential. Both configurations require disabling TLS 1.0, TLS 1.1 and TLS 1.2 in CBC mode.

The deciding factor is the arrival date of a Cryptographically Relevant Quantum Computer. No CRQC exists as of 2026. In its [2025 Quantum Threat Timeline Report](https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/), the Global Risk Institute reports that the surveyed experts put the probability of a CRQC at 28 to 49% within ten years and 51 to 70% within fifteen years. The NIST draft [IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) proposes to disallow quantum-vulnerable public-key algorithms after 2035. We use 2035 as the planning date. By Mosca's inequality, data is at risk when its remaining confidentiality lifetime plus the time needed to migrate exceeds the time before a CRQC becomes available.
- TLS 1.3 with a classical key exchange suffices for showcase websites and for data that loses its sensitivity before 2035, such as one-time passcodes, session tokens with a fixed expiry, or embargoed announcements. A showcase site with a contact form or an account area collects personal data and falls under the next case.
- TLS 1.3 paired with ML-KEM is recommended for data that is sensitive today and will still be sensitive after 2035. Examples are health and genomic records, identity and biometric data, legal and financial records, trade secrets, infrastructure plans, and state or defense communications. Each surveyed sector handles data of this kind, yet even in energy, the sector with the highest post-quantum share at 43.0%, 57.0% of domains negotiate a classical key exchange by default.

A host that serves both kinds of data should follow the ML-KEM recommendation. These recommendations concern the key exchange only. As section iii explains, the classical certificate chain does not affect the confidentiality of completed sessions.


