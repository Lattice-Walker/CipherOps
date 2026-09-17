# Security, and post-quantum security assessment of TLS

Write $x \mathbin\| y$ for concatenation, $|x|$ for byte length, $\oplus$ for bitwise XOR, and $[x]_n$ for the $n$-byte big-endian encoding of an integer $x$. For a byte string $X$ we write $X[i]$ for its $i$-th byte, indexed from zero, and $X[i \,..\, j]$ for the substring from $X[i]$ to $X[j]$ inclusive, with the convention that $X[i \,..\, i-1]$ is the empty string. The convention is needed rather than decorative: a record of length zero is admissible, and then $\mathrm{strip}$ below has upper index $-1$. Subscripts are reserved for blocks: $P_j$ is the $j$-th $b$-byte block of $P$. Thus $P_4[15]$ is the last byte of the fourth block, and no expression below uses a subscript to mean a byte.

Fix a block cipher $E : \{0,1\}^{8k} \times \{0,1\}^{8b} \to \{0,1\}^{8b}$ with block size $b$ bytes and decryption algorithm $D$, and a MAC $\mathrm{MAC} : \{0,1\}^{8k_a} \times \{0,1\}^{*} \to \{0,1\}^{8t}$ with tag size $t$ bytes. A record layer is a stateful pair $(\mathrm{Send}, \mathrm{Recv})$ over a state $\sigma = (K, \mathit{SQN}, \nu)$, where $K = (K_e, K_a)$ is the key material, $\mathit{SQN} \in \{0,\dots,2^{64}-1\}$ is a sequence number incremented once per record, and $\nu$ is the IV state, used only by the chained-IV versions.

A version of the protocol is a tuple $\Lambda_V = (\mathrm{Encode}, \Pi_V, \Phi_V, \mathrm{IV}_V, \mathcal{A}_V)$, where $\Pi_V$ is a parsing predicate applied on decryption, $\Phi_V$ is a selector naming the data on which the MAC is verified, $\mathrm{IV}_V$ is the rule producing $C_0$, and $\mathcal{A}_V$ is the set of admissible parameters $(t,b)$. We write $\Lambda_V[t,b]$ for the scheme with those parameters fixed. Since $\mathrm{Send}$ samples an IV in two of the three versions, $\Lambda_V[t,b]$ is a randomised algorithm, and equality between two such schemes below means that their outputs are identically distributed for every input and state.

## 1. Breaking TLS 1.2 CBC-mode

{% include-markdown "Lattice-Walker/CipherOps/articles/post-quantum-algorithms/TLS-1-2.md" %}

## 2. Breaking TLS 1.0 and TLS 1.1

{% include-markdown "Lattice-Walker/CipherOps/articles/post-quantum-algorithms/TLS-1-0-1-1.md" %}


## 3. Safety of TLS 1.2 with AEAD-only cipher suites 

## 4. Safety of TLS 1.3

## 5. Breaking HNDL-safety of non post-quantum versions of TLS 1.2 and 1.3

## 6. ML-KEM and the HNDL-security of TLS 1.2 and 1.3
