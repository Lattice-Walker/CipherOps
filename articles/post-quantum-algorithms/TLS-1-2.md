The attack of Section 1.4 is from [Tag Size Does Matter: Attacks and Proofs for
the TLS Record Protocol](https://www.iacr.org/archive/asiacrypt2011/70730368/70730368.pdf) ; the presentation below reorganises it around a single claim and supplies the statistical and game-based accounting explicitly.

### 1.1 The protocols

Write $x \mathbin\| y$ for concatenation, $|x|$ for byte length, $\oplus$ for bitwise XOR, and $[x]_n$ for the $n$-byte big-endian encoding of an integer $x$. For a byte string $X$ we write $X[i]$ for its $i$-th byte, indexed from zero, and $X[i \,..\, j]$ for the substring from $X[i]$ to $X[j]$ inclusive, with the convention that $X[i \,..\, i-1]$ is the empty string. The convention is needed rather than decorative: a record of length zero is admissible, and then $\mathrm{strip}$ below has upper index $-1$. Subscripts are reserved for blocks: $P_j$ is the $j$-th $b$-byte block of $P$. Thus $P_4[15]$ is the last byte of the fourth block, and no expression below uses a subscript to mean a byte.

Fix a block cipher $E : \{0,1\}^{8k} \times \{0,1\}^{8b} \to \{0,1\}^{8b}$ with block size $b$ bytes and decryption algorithm $D$, and a MAC $\mathrm{MAC} : \{0,1\}^{8k_a} \times \{0,1\}^{*} \to \{0,1\}^{8t}$ with tag size $t$ bytes. A record layer is a stateful pair $(\mathrm{Send}, \mathrm{Recv})$ over a state $\sigma = (K, \mathit{SQN}, \nu)$, where $K = (K_e, K_a)$ is the key material, $\mathit{SQN} \in \{0,\dots,2^{64}-1\}$ is a sequence number incremented once per record, and $\nu$ is the IV state, used only by the chained-IV versions.

A version of the protocol is a tuple $\Lambda_V = (\mathrm{Encode}, \Pi_V, \Phi_V, \mathrm{IV}_V, \mathcal{A}_V)$, where $\Pi_V$ is a parsing predicate applied on decryption, $\Phi_V$ is a selector naming the data on which the MAC is verified, $\mathrm{IV}_V$ is the rule producing $C_0$, and $\mathcal{A}_V$ is the set of admissible parameters $(t,b)$. We write $\Lambda_V[t,b]$ for the scheme with those parameters fixed. Since $\mathrm{Send}$ samples an IV in two of the three versions, $\Lambda_V[t,b]$ is a randomised algorithm, and equality between two such schemes below means that their outputs are identically distributed for every input and state.

#### 1.1.2 TLS 1.0

The IV is chained: $C_0$ for record $i$ is the last ciphertext block of record $i-1$, so $\nu \leftarrow C_{|P|/b}$ after each send, and the IV is not transmitted. RFC 2246 fixes neither how a receiver verifies the padding nor what it does when verification fails, so TLS 1.0 does not determine a single $\Phi$. Two binary choices are left open: which predicate is used, $\Pi_{\mathrm{strict}}$ or $\Pi_{\mathrm{len}}$, and what happens when it fails, namely rejection without a MAC or a MAC over $\mathrm{strip}_0(P)$. This gives four receiver families, and the grid is exhaustive for these two choices:

$$
\begin{array}{l|cc}
 & \text{reject as } \bot & \text{MAC over } \mathrm{strip}_0(P) \\ \hline
\text{predicate } \Pi_{\mathrm{strict}} & \mathsf{R}_{\mathrm{strict}} & \mathsf{R}_{\mathrm{mac}} \\
\text{predicate } \Pi_{\mathrm{len}} & \mathsf{R}_{\mathrm{len}} & \mathsf{R}_{\mathrm{len}\text{-}\mathrm{mac}}
\end{array}
$$

In each family the accepting branch is $\Phi(P) = \mathrm{strip}(P)$; the families differ only in the predicate guarding that branch and in the value taken when it fails. Thus $\mathsf{R}_{\mathrm{mac}}$ is exactly the selector $\Phi_{1.1}$ of Section 1.1.4, and $\mathsf{R}_{\mathrm{strict}}$ is

$$
\Phi(P) =
\begin{cases}
\mathrm{strip}(P), & \text{if } \Pi_{\mathrm{strict}}(P) \\[2pt]
\bot, & \text{otherwise,}
\end{cases}
$$

with $\mathsf{R}_{\mathrm{len}}$ and $\mathsf{R}_{\mathrm{len}\text{-}\mathrm{mac}}$ obtained by substituting $\Pi_{\mathrm{len}}$ for $\Pi_{\mathrm{strict}}$. The symbol $\bot$ means that no MAC is computed and the record is rejected. Section 1.5 breaks the two families in the first row and shows why the argument does not reach the second row. The admissible parameters are $t \in \{16, 20\}$, for HMAC-MD5 and HMAC-SHA-1, with $b \in \{8, 16\}$.

Exhaustiveness is claimed only for these two choices. A receiver may depart from the grid in some third way, verifying only part of the pattern, or selecting a third MAC input on failure. Such a receiver is governed by (H3) below and is outside every statement in this document.

#### 1.1.3 TLS 1.1

Two coordinates change. The IV becomes explicit and freshly sampled, $C_0 \xleftarrow{\$} \{0,1\}^{8b}$ per record, transmitted with the record, so $\nu$ leaves the state. The padding check is strict and mandatory, and the MAC is computed unconditionally:

$$
\Phi_{1.1}(P) =
\begin{cases}
\mathrm{strip}(P), & \text{if } \Pi_{\mathrm{strict}}(P) \\[2pt]
\mathrm{strip}_0(P), & \text{otherwise.}
\end{cases}
$$

That is, on a padding failure the receiver proceeds as if the padding had length zero, verifies a MAC on that input, and returns a single error that does not distinguish the two branches. The admissible parameters are unchanged: $t \in \{16, 20\}$, $b \in \{8, 16\}$.

#### 1.1.4 TLS 1.2

The record layer is inherited from TLS 1.1 without alteration: the same explicit IV rule, the same $\Pi_{\mathrm{strict}}$, and

$$\Phi_{1.2} = \Phi_{1.1}.$$

What changes is the parameter set. TLS 1.2 adds HMAC-SHA-256, so $t \in \{16, 20, 32\}$, deprecates DES, and admits a second, disjoint record construction in which the record is protected by an authenticated encryption algorithm and neither $\Pi$ nor $\Phi$ is defined. That second construction is outside the scope of this document; *the special case of TLS 1.2* means throughout the scheme $\Lambda_{1.2}[20,16]$, that is, a CBC-mode ciphersuite with AES and HMAC-SHA-1.




