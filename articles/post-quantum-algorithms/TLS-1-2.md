https://pure.tue.nl/ws/portalfiles/portal/3870148/17800025343027.pdf

https://www.ieee-security.org/TC/SP2013/papers/4977a526.pdf


The attack of Section 1.4 is from [Tag Size Does Matter: Attacks and Proofs for
the TLS Record Protocol](https://www.iacr.org/archive/asiacrypt2011/70730368/70730368.pdf) ; the presentation below reorganises it around a single claim and supplies the statistical and game-based accounting explicitly.

### 1.1 TLS 1.2

The record layer is inherited from TLS 1.1 without alteration: the same explicit IV rule, the same $\Pi_{\mathrm{strict}}$, and

$$\Phi_{1.2} = \Phi_{1.1}.$$

What changes is the parameter set. TLS 1.2 adds HMAC-SHA-256, so $t \in \{16, 20, 32\}$, deprecates DES, and admits a second, disjoint record construction in which the record is protected by an authenticated encryption algorithm and neither $\Pi$ nor $\Phi$ is defined. That second construction is outside the scope of this document; *the special case of TLS 1.2* means throughout the scheme $\Lambda_{1.2}[20,16]$, that is, a CBC-mode ciphersuite with AES and HMAC-SHA-1.

### 1.2 Hypotheses

### 1.3 The attack




