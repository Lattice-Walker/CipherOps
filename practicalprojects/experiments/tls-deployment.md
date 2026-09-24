# TLS in Practice: A Sector-by-Sector Survey of Present and Post-Quantum Risk

## i. The deprecated TLS protocols

We have shown in [Breaking TLS 1.2 CBC mode, TLS 1.1, and TLS 1.0](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FTLS-12CBC-11-10.md) that TLS 1.2 CBC mode, TLS 1.1, and TLS 1.0 are deprecated. The failures are structural rather than incidental: CBC mode in TLS inherits a MAC-then-encrypt construction whose padding check leaks through timing, and TLS 1.0 and 1.1 additionally depend on hash and PRF constructions that no longer meet any current standard. None of these weaknesses is repairable within the protocol version that exhibits them, which is why the remedy has always been migration rather than patching.

Furthermore, we have shown in [Deprecated TLS risk assessment and post-quantum risk assessment](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fgovernance%2FTLS-risk-assessment.md) that the risk is CVSS v4.0 Score: 6.3 / Medium. Deprecation, however, is a statement about a protocol, not about a fleet. A server does not stop being reachable over TLS 1.0 because the specification declaring it obsolete has been published; it stops when an administrator changes a configuration file. This distinction is what the present study is built to measure, and it separates into two questions that are easy to conflate. The first is what a server negotiates by default, which describes the protection a normal visitor actually receives. The second is what a server accepts, which describes the protection available to an attacker who is free to propose whatever the server will tolerate. A host that defaults to TLS 1.3 while still accepting TLS 1.0 offers the first answer to its users and the second to its adversaries, and only the second bounds the risk. We therefore report both throughout.

## ii. TLS 1.2 AEAD mode and TLS 1.3

We have shown in [The Security of TLS 1.2 AEAD mode and TLS 1.3](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FTLS-12AEAD-13.md) that TLS 1.2 AEAD mode and TLS 1.3 are cryptographically secure. Against any adversary bounded by classical computation, the guarantees hold: authenticated encryption closes the padding-oracle class of attacks outright, and ephemeral key exchange provides forward secrecy, so compromising a server's long-term key tomorrow does not retroactively open the sessions it completed today. A host in this configuration is correctly described as secure against the adversary the protocols were designed for.

The exchange in these configurations is classical (ECDHE over X25519 or a NIST curve) and its security rests on a discrete logarithm that Shor's algorithm solves. An adversary who records a handshake today and gains a cryptographically relevant quantum computer at any point within the confidentiality lifetime of that traffic recovers the session key and decrypts it. This is the harvest-now-decrypt-later problem, and we have shown in [Deprecated TLS risk assessment and post-quantum risk assessment](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fgovernance%2FTLS-risk-assessment.md) that TLS 1.2 AEAD mode and TLS 1.3 lack HNDL security. Under the [HNDL safety scoring method](https://lattice-walker.github.io/CipherOps/display_practicalprojects/practicalprojects.html#article=practicalprojects%2FTools%2FHNDL-CVSS-calculator.md) we established, we found that they were SHNDL score: 8.2 High.

A CVSS v4.0 score of 6.3 and an SHNDL score of 8.2 are not points on a common scale, and the higher number does not mean the modern protocols are "worse" than the deprecated ones. They answer different questions: CVSS asks what an adversary can do now, SHNDL asks what a recorded session is worth later. What the pairing establishes is that a fleet can be fully migrated off every deprecated protocol, score well on every present-day assessment, and remain entirely exposed on the forward-looking one. Security here is not a single axis along which a deployment moves forward, and a survey that measured only deprecation would report such a fleet as healthy.

This is why the measurements that follow separate TLS 1.2 AEAD mode and TLS 1.3 from TLS 1.3 paired with a post-quantum key exchange, rather than grouping them as "modern TLS". The distinction is not one of cipher strength or protocol version but of which hard problem the session key ultimately rests on, and it is the only distinction that determines whether traffic captured today remains confidential.

## iii. TLS 1.3 paired with ML-KEM

We have shown in [The post quantum security of TLS 1.3 ML KEM](https://lattice-walker.github.io/CipherOps/display_articles/articles.html#article=articles%2Fpost-quantum-algorithms%2FHNDL-TLS-12-13.md) that TLS 1.3 paired with ML KEM is HNDL safe. The deployed form of this is a hybrid group (X25519MLKEM768) in which the client offers a single key share carrying both an X25519 public key and an ML-KEM-768 encapsulation key, and the session secret is derived from both results together. The derived key is secure if either component is secure. A cryptanalytic break of ML-KEM leaves the classical X25519 exchange intact, and a quantum adversary who solves the discrete logarithm still faces the lattice problem. 

The handshake authenticates as well as exchanges keys, and the certificate chain in these connections remains classical RSA or ECDSA. 
- Authentication is a claim about the present: the signature proves the server is who it says it is at the moment of the handshake. An adversary who acquires the ability to forge that signature in ten years can impersonate the server in ten years, but cannot reach back and decrypt a session that has already completed.
- Confidentiality is the property that is retroactively attackable, and confidentiality is the property the key exchange determines.

Post-quantum authentication is a separate problem; it is not part of the harvest-now-decrypt-later problem, and it is not what this survey measures.









## 1. Banking sector

Default TLS protocol — Banques
Share of 92 reachable domains (11 unreachable excluded).

![Banking sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Banques_tls_default_protocols.svg)

![Banking sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Banques_tls_supported_protocols.svg)

## 2. Energy sector

Default TLS protocol — Énergie
Share of 107 reachable domains (22 unreachable excluded).

![Energy sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Energie_tls_default_protocols.svg)

![Energy sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Energie_tls_supported_protocols.svg)

## 3. Defense sector

Default TLS protocol — Défense
Share of 85 reachable domains (15 unreachable excluded).

![Defense sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Defense_tls_default_protocols.svg)

![Defense sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Defense_tls_supported_protocols.svg)

## 4. Medical sector

Default TLS protocol — Hôpitaux
Share of 119 reachable domains (13 unreachable excluded).
Slices below 3.5° are drawn at 3.5° so they stay visible; the percentages shown are exact.

![Medical sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Hopitaux_tls_default_protocols.svg)

![Medical sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Hopitaux_tls_supported_protocols.svg)

## 5. Governemental sector

Default TLS protocol — Gouvernement
Share of 1251 reachable domains (43 unreachable excluded).
Slices below 3.5° are drawn at 3.5° so they stay visible; the percentages shown are exact.

![Governemental sector default protocol](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Gouv_tls_default_protocols.svg)

![Governemental sector supported protocols](https://lattice-walker.github.io/CipherOps/practicalprojects/experiments/tls_deployment_images/Gouv_tls_supported_protocols.svg)

