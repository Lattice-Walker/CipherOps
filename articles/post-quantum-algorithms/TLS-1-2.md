https://pure.tue.nl/ws/portalfiles/portal/3870148/17800025343027.pdf

https://www.ieee-security.org/TC/SP2013/papers/4977a526.pdf


The attack of Section 1.4 is from [Tag Size Does Matter: Attacks and Proofs for
the TLS Record Protocol](https://www.iacr.org/archive/asiacrypt2011/70730368/70730368.pdf) ; the presentation below reorganises it around a single claim and supplies the statistical and game-based accounting explicitly.

### 1.1 The protocols

Write $x \mathbin\| y$ for concatenation, $|x|$ for byte length, $\oplus$ for bitwise XOR, and $[x]_n$ for the $n$-byte big-endian encoding of an integer $x$. For a byte string $X$ we write $X[i]$ for its $i$-th byte, indexed from zero, and $X[i \,..\, j]$ for the substring from $X[i]$ to $X[j]$ inclusive, with the convention that $X[i \,..\, i-1]$ is the empty string. The convention is needed rather than decorative: a record of length zero is admissible, and then $\mathrm{strip}$ below has upper index $-1$. Subscripts are reserved for blocks: $P_j$ is the $j$-th $b$-byte block of $P$. Thus $P_4[15]$ is the last byte of the fourth block, and no expression below uses a subscript to mean a byte.

Fix a block cipher $E : \{0,1\}^{8k} \times \{0,1\}^{8b} \to \{0,1\}^{8b}$ with block size $b$ bytes and decryption algorithm $D$, and a MAC $\mathrm{MAC} : \{0,1\}^{8k_a} \times \{0,1\}^{*} \to \{0,1\}^{8t}$ with tag size $t$ bytes. A record layer is a stateful pair $(\mathrm{Send}, \mathrm{Recv})$ over a state $\sigma = (K, \mathit{SQN}, \nu)$, where $K = (K_e, K_a)$ is the key material, $\mathit{SQN} \in \{0,\dots,2^{64}-1\}$ is a sequence number incremented once per record, and $\nu$ is the IV state, used only by the chained-IV versions.

A version of the protocol is a tuple $\Lambda_V = (\mathrm{Encode}, \Pi_V, \Phi_V, \mathrm{IV}_V, \mathcal{A}_V)$, where $\Pi_V$ is a parsing predicate applied on decryption, $\Phi_V$ is a selector naming the data on which the MAC is verified, $\mathrm{IV}_V$ is the rule producing $C_0$, and $\mathcal{A}_V$ is the set of admissible parameters $(t,b)$. We write $\Lambda_V[t,b]$ for the scheme with those parameters fixed. Since $\mathrm{Send}$ samples an IV in two of the three versions, $\Lambda_V[t,b]$ is a randomised algorithm, and equality between two such schemes below means that their outputs are identically distributed for every input and state.


#### 1.1.1 TLS 1.2

The record layer is inherited from TLS 1.1 without alteration: the same explicit IV rule, the same $\Pi_{\mathrm{strict}}$, and

$$\Phi_{1.2} = \Phi_{1.1}.$$

What changes is the parameter set. TLS 1.2 adds HMAC-SHA-256, so $t \in \{16, 20, 32\}$, deprecates DES, and admits a second, disjoint record construction in which the record is protected by an authenticated encryption algorithm and neither $\Pi$ nor $\Phi$ is defined. That second construction is outside the scope of this document; *the special case of TLS 1.2* means throughout the scheme $\Lambda_{1.2}[20,16]$, that is, a CBC-mode ciphersuite with AES and HMAC-SHA-1.




