# Plaintext recovery against TLS 1.2 CBC mode

We formalise the TLS 1.2 Record Protocol in CBC mode as a stateful, length-hiding authenticated-encryption scheme, and study its confidentiality when decryption exposes a timing side channel.

The main result is that in this leakage model MEE-TLS-CBC provides no confidentiality. An explicit adversary, a reconstruction of the [Lucky Thirteen attack of AlFardan and Paterson](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf), recovers any target plaintext block lying within a record with advantage exactly 1 and under no cryptographic assumption, from at most $2^{16} + 43 + 14\cdot 2^8$ decryption sessions of one query each. In a noisy variant of the model, the same recovery succeeds with $L = O\!\big((\sigma_{\!\eta}/c_0)^2 \log(M/\epsilon)\big)$ repetitions per query.

**Definition i (Bytes)** 
- A *byte* is an element of $\mathbb{B} = \{0,1\}^8$, identified with an integer in $[0,255]$ where convenient. 
- $\mathbb{B}^n$ is the set of $n$-byte strings and $\mathbb{B}^* = \bigcup_{n \ge 0} \mathbb{B}^n$. 
- Let $|x|$ be the lenght in bytes of $x \in \mathbb{B}^*$
- Let $x[i]$ be its $i$-th byte counting from $0$
- Let $x[i \mathinner{.\,.} j]$ be the substring from byte $i$ to byte $j$ inclusive, understood as the empty string when $j < i$. 
- We write $x \,\|\, y$ for concatenation, $\langle p \rangle^{n}$ for the $n$-byte string every byte of which equals $p$, and $\langle m \rangle_k$ for the $k$-byte big-endian encoding of an integer $m$. 
- A string whose length is a multiple of $b$ is parsed as $x = x_1 \,\|\, \cdots \,\|\, x_n$ with each $|x_i| = b$.
- Let $\lceil x \rceil$ be the least integer $\ge x$, including for negative $x$, so that $\lceil -30/64 \rceil = 0$. 

Three parameters are fixed throughout: the block size $b$, the MAC tag length $t$, and the length $h$ of the string prepended to a record before the MAC is computed. TLS 1.2 fixes $h = 13$, being an 8-byte sequence number followed by a 5-byte record header [[LT, §2]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf). The instantiation under analysis is $b = 16$ (AES) and $t = 20$ (HMAC-SHA-1).



### 1.1. TLS 1.2 CBC mode

**Definition ii (Encryption Schemes)**
- A stateful authenticated encryption scheme with associated data is a triple $\Pi = (\mathsf{Gen}, \mathsf{Enc}, \mathsf{Dec})$ of algorithms over a header space $\mathcal{H} = \mathbb{B}^5$ and a record space $\mathcal{R} = \mathbb{B}^*$.
    - $\mathsf{Gen}(1^\kappa)$, where $\kappa$ is the security parameter governing the key lengths, is randomised and outputs a key pair $K = (K_e, K_a)$ together with an initial state $\sigma_0$. A state is a pair $\sigma = (\mathit{sqn}_s, \mathit{sqn}_r)$ of integers in $[0, 2^{64})$, the sending and receiving sequence numbers, with $\sigma_0 = (0,0)$.
    - $\mathsf{Enc}_K(\mathrm{HDR}, R; \sigma)$ is randomised and outputs a ciphertext $C \in \mathbb{B}^*$ and an updated state. $\mathsf{Dec}_K(\mathrm{HDR}, C; \sigma)$ is deterministic and outputs either a record $R \in \mathcal{R}$ or the distinguished failure symbol $\bot$, together with an updated state. Correctness requires that for every key, every header and every record, encrypting and then decrypting under matched states returns the record.

We adopt this syntax from [PRS11](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20), which is the framework in which MEE-TLS-CBC has been proved secure.

**Definition iii (Adversary)** Let $E : \{0,1\}^{\kappa} \times \mathbb{B}^{b} \to \mathbb{B}^{b}$ be a block cipher with inverse $D$, so $D_{K_e}(E_{K_e}(x)) = x$ for all $x$. We assume $E$ is a secure pseudorandom permutation: for every efficient $\mathcal{B}$,

$$\mathbf{Adv}^{\mathrm{prp}}_{E}(\mathcal{B}) = \left| \Pr\big[\mathcal{B}^{E_{K_e}(\cdot), E^{-1}_{K_e}(\cdot)} = 1\big] - \Pr\big[\mathcal{B}^{\pi(\cdot), \pi^{-1}(\cdot)} = 1\big] \right|$$ is small, the second probability being over a uniform permutation $\pi$ of $\mathbb{B}^b$.

**Definition iv (MAC)** Let $\mathrm{MAC}_{K_a} : \mathbb{B}^* \to \mathbb{B}^{t}$ be $\mathrm{HMAC}\text{-}H$ for $H \in \{\mathrm{MD5}, \mathrm{SHA\text{-}1}, \mathrm{SHA\text{-}256}\}$, with corresponding tag lengths $t \in \{16, 20, 32\}$. 

These are the three algorithms considered here and in [[LT]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf); TLS 1.2 additionally admits HMAC-SHA-384 through RFC 5289 and RFC 5487, which [[LT, §2.1 fn. 3]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) excludes from its analysis and which is likewise outside the scope of Proposition 9, since SHA-384 has a 128-byte block and a 16-byte length encoding. We assume the MAC is strongly unforgeable under chosen-message attack, and write $\mathbf{Adv}^{\mathrm{suf\text{-}cma}}_{\mathrm{MAC}}(\mathcal{C})$ for the corresponding advantage. The MAC key satisfies $|K_a| \le 64$, as it does for all three algorithms (keys of 16, 20 or 32 bytes); this bound is used in Proposition 9.


#### 1.1.1 Encoding

The encoding step is where MEE-TLS-CBC departs from a generic MAC-then-encrypt construction, and reproducing it exactly is what makes the attack possible; a treatment that abstracts the padding away cannot express the attack at all.

![Encode](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/encode.svg)


**Definition 1 (encoding).** For a record $R$, a tag $T \in \mathbb{B}^t$ and an integer $j \ge 0$, set

$$p_{\min}(R) = b - 1 - \big((|R| + t) \bmod b\big), \qquad p = p_{\min}(R) + jb,$$

and define $\mathsf{Encode}(R, T; j) = R \,\|\, T \,\|\, \langle p \rangle^{p+1}$, which is defined whenever $p \le 255$. The parameter $j$ is the number of additional whole blocks of padding beyond the minimum.

**Proposition 2.** $p_{\min}(R) \in [0, b-1]$, and $|\mathsf{Encode}(R,T;j)| = |R| + t + p + 1$ is a positive multiple of $b$ for every $j \ge 0$ with $p \le 255$. Moreover every legal padding arises this way, since a total length divisible by $b$ forces $p$ to exceed $p_{\min}$ by a whole number of blocks.

*Proof.* $(|R|+t) \bmod b$ lies in $[0, b-1]$, so $p_{\min}$ does too. For $j = 0$ we get $|R| + t + p_{\min} + 1 = |R| + t + b - \big((|R|+t) \bmod b\big) \equiv 0 \pmod b$, and it is at least $b > 0$. Adding $jb$ to $p$ adds $jb$ to the total, preserving both properties. For the converse, if $R \,\|\, T \,\|\, \langle p \rangle^{p+1}$ has length divisible by $b$ then $p + 1 \equiv -(|R|+t) \pmod b$, which together with $p \ge 0$ forces $p \in \{p_{\min}, p_{\min}+b, \dots\}$. $\square$

#### 1.1.2 Encryption

![Encryption](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/encrypt.svg)

**Definition 3 (encryption).** $\mathsf{Enc}_K(\mathrm{HDR}, R; \sigma)$, with $j$ an implementation-chosen number of extra padding blocks:

1. $T \leftarrow \mathrm{MAC}_{K_a}\big(\langle \mathit{sqn}_s \rangle_8 \,\|\, \mathrm{HDR} \,\|\, R\big)$.
2. $P \leftarrow \mathsf{Encode}(R, T; j)$, parsed as $P_1 \,\|\, \cdots \,\|\, P_n$.
3. $C_0 \leftarrow_{\$} \mathbb{B}^{b}$, the explicit IV mandated by TLS 1.2.
4. $C_i \leftarrow E_{K_e}(P_i \oplus C_{i-1})$ for $i = 1, \dots, n$.
5. $\mathit{sqn}_s \leftarrow \mathit{sqn}_s + 1$; return $C = C_0 \,\|\, C_1 \,\|\, \cdots \,\|\, C_n$.

The sequence number is authenticated but not transmitted: the receiver supplies its own copy in step 7 of Definition 4. Every forgery in §1.2 is therefore verified against a sequence number the adversary never has to produce or modify, which allows the attack ciphertexts to be assembled out of captured blocks alone.

#### 1.1.3 Decryption

![Decryption](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/decrypt.svg)

**Definition 4 (decryption).** $\mathsf{Dec}_K(\mathrm{HDR}, C; \sigma)$:

1. If $|C| \bmod b \ne 0$, or $n := |C|/b - 1 < 1$, or $nb < t + 1$, return $\bot$ without further processing.
2. $P_i \leftarrow D_{K_e}(C_i) \oplus C_{i-1}$ for $i = 1, \dots, n$; set $P \leftarrow P_1 \,\|\, \cdots \,\|\, P_n$ and $\ell_P \leftarrow nb$.
3. $p \leftarrow P[\ell_P - 1]$, read as an integer in $[0,255]$.
4. Set $\mathit{wf} \leftarrow \mathsf{true}$ iff $\ell_P \ge p + 1 + t$ and, *evaluated only if that test passes*, $P[\ell_P - 1 - i] = p$ for every $0 \le i \le p$.
5. If $\mathit{wf}$ then $r \leftarrow \ell_P - p - 1 - t$, else $r \leftarrow \ell_P - t$.
6. $R \leftarrow P[0 \mathinner{.\,.} r-1]$ and $T \leftarrow P[r \mathinner{.\,.} r+t-1]$.
7. Let $v \leftarrow \big[\mathrm{MAC}_{K_a}\big(\langle \mathit{sqn}_r \rangle_8 \,\|\, \mathrm{HDR} \,\|\, R\big) = T\big]$; then set $\mathit{sqn}_r \leftarrow \mathit{sqn}_r + 1$ and return $R$ if $v$, else $\bot$.

The ordering in step 7 matters: the tag is verified against the *current* receive counter and the increment follows, matching the sender's use of $\mathit{sqn}_s$ in step 1 of Definition 3. Incrementing first would make correctness fail on every honest record.

The sanity test in step 1 reserves room for a zero-length record, a full tag and one padding byte, and rejects before any cryptographic work is done; it agrees with the normative procedure of [[LT, §7, p. 16]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf). This matters because a record rejected at step 1 produces no MAC computation, so no value of $\mathsf{cost}$ is defined for it. 

Step 5 is the vulnerability, its purpose is to defeat the padding oracle of [[CHVV03]](https://www.scilit.com/publications/7a4b73573841857d9102de26df89dbd3) by having a MAC verified on every path, and in that it succeeds completely: the return value is $\bot$ in both branches and distinguishes nothing. What it cannot conceal is that the two branches hand HMAC strings of different lengths. 

The else-branch of step 5 is the one prescribed by RFC 4346 and RFC 5246. Implementations that instead strip $\mathit{padlen}+1$ bytes and then read the tag (GnuTLS-style) induce a different case analysis and, per [[LT, §6.1]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf), a larger timing signal; that variant is not covered here.


**Hypothesis 5 (compliant underflow handling).** We assume the receiver implements step 4's length test and, when it fails, proceeds to the else-branch of step 5. 

This is what [[LT, §7, p. 16–17]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) prescribes, so the hypothesis is one of RFC-compliance rather than a fresh assumption; but it is a genuine restriction, because [[LT, §6, p. 15]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) documents a real implementation that instead skips MAC verification entirely on underflow, and builds a distinguisher on that behaviour in which the branch is reached with probability 1. Against such a receiver the results of §1.3 do not apply. Against a receiver satisfying the hypothesis the branch is unreachable by construction. For a receiver that skips, reaching the branch through the attack ciphertext of Section 2 requires $\mathit{wf}$'s byte test to pass while its length test fails, which at $\ell_P = 64$ and $t = 20$ forces $p \in [44, 63]$ and hence a constant self-describing pattern of at least 45 bytes, at least 29 of which lie outside the block the adversary controls; summing $2^{-8(p-15)}$ over that range gives less than $2^{-231}$ per query. Both the bound and its derivation are specific to $\ell_P = 64$: at $\ell_P = 32$ the skip branch is instead reachable near-deterministically (for $p \in [12,31]$ the matching pattern fits inside the single controlled block, so the adversary forces it), which is a further reason the analysis fixes the four-block geometry $\ell_P = 64$. The hypothesis constrains the plaintext-recovery game of Definition 12, not the distinguishing game of Definition 13.

**Hypothesis 6 (constant-time padding comparison).** We assume the receiver's padding-format check in step 4 runs in time independent of the plaintext. 

This isolates the MAC as the only plaintext-dependent contribution to decryption time, which is what makes Model A's leakage $\mathsf{cost}(\lambda(P))$ alone. It is a genuine and separate assumption: a natural early-exit comparison costs $p+1$ byte-comparisons on a valid Case-2 run of length $p+1$ but exits at once on a Case-3 mismatch, so its cost is *sign-correlated* with the case (the fast bucket, Case 2, carries the larger scan), and it perturbs the very quantity Theorem 3 measures. [[LT, §3.1]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) observes this padding-removal channel directly, noting it runs opposite to the MAC signal and, per [[LT, §5]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf), is dominated by it. The assumption is therefore not needed for the attack to succeed, since an early-exit scan only adds leakage, and for the recovery masks (padding length 1 in Phase 1, at most 16 in Phase 2) the added bias is at most 16 byte-comparisons against a compression function of hundreds of cycles. It is needed, however, for the clean two-mean form of Theorem 3, whose exact means $4c_0$ and $5c_0$ are stated under it.

#### 1.1.4 The leakage function

![HMAC input length](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/hmac-lenght.svg)

**Definition 7 (HMAC input length).** For a decrypted plaintext $P$, let $\lambda(P) = h + r$ with $r$ as computed in step 5 of Definition 4. Explicitly,

$$\lambda(P) = \begin{cases} h + \ell_P - t - 1 - p & \text{if the padding is well-formed,} \\ h + \ell_P - t & \text{otherwise.} \end{cases}$$

Since $r \ge 0$ on both branches (step 1 guarantees $\ell_P \ge t+1$, and step 4 guarantees $\ell_P \ge p+1+t$ when it passes), we have $\lambda(P) \ge h = 13$ for every $P$ reaching step 5.

![HMAC cost](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/hmac-cost.svg)


**Definition 8 (cost).** For a hash function $H$ with a 64-byte block, an 8-byte length encoding and a digest of $d$ bytes, $\mathsf{cost}_{H}(\ell)$ is the number of compression-function evaluations of $H$ performed by one $\mathrm{HMAC}\text{-}H$ computation over an $\ell$-byte message, $\ell \ge 0$. The dependence on $H$ is suppressed where no ambiguity arises, but it is real: the count depends on $d$ as well as on $\ell$.

**Proposition 9.** Let $H$ have a 64-byte block, an 8-byte length encoding and a digest length $d$ with $0 \le d \le 55$, and let the MAC key satisfy $|K_a| \le 64$. Then for every $\ell \ge 0$,

$$\mathsf{cost}_{H}(\ell) = \left\lceil \frac{\ell - 55}{64} \right\rceil + 4 .$$

*Proof.* $\mathrm{HMAC}_{K_a}(M) = H\big((K_a \oplus \mathit{opad}) \,\|\, H((K_a \oplus \mathit{ipad}) \,\|\, M)\big)$, where $K_a$ is zero-padded to 64 bytes (this is where $|K_a| \le 64$ is used, a longer key being hashed first), so each of the two invocations of $H$ is fed one full 64-byte block ahead of its payload [[LT, §2.1]]. Each $H$ processes its input in 64-byte chunks after Merkle–Damgård strengthening appends an $\texttt{0x80}$ byte, zero or more zero bytes, and an 8-byte length field, rounding up to a multiple of 64; the appended material is therefore at least 9 bytes. The inner invocation consumes $\big\lceil (64 + \ell + 9)/64 \big\rceil = 1 + \lceil (\ell+9)/64 \rceil$ blocks, and since $\lceil x + 1\rceil = \lceil x \rceil + 1$ for every real $x$, $\lceil (\ell+9)/64 \rceil = \lceil (\ell-55)/64 \rceil + 1$; so the inner count is $\lceil (\ell-55)/64 \rceil + 2$. The outer invocation consumes $\lceil (64 + d + 9)/64 \rceil$ blocks, which is exactly 2 whenever $0 \le d \le 55$. Summing gives the claim. $\square$

The hypothesis on $d$ is tight: for $d = 56$ the outer invocation consumes $\lceil (64+56+9)/64 \rceil = 3$ blocks, and the count exceeds the closed form by one for every $\ell$. The constant 55 is $64 - 8 - 1$, the largest payload that still fits beside the minimum strengthening in a single chunk. For untruncated HMAC $d = t$, so the hypothesis reads $t \le 55$ and holds for all three algorithms of Section 1; for the truncated tags of RFC 6066, which [[LT, §4.3]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) also considers, $d$ remains the full digest length and $t$ does not enter the count at all.

**Corollary 10.** $$\mathsf{cost}(\ell)=\begin{cases}4&\forall\ell\in[0,55],\\5&\forall\ell=-\in\{56,119\},\\6&\forall\ell\in\{120,280\}.\end{cases}$$

The domain matters. Extended by its closed form to negative arguments, the function is *not* constant below 55: the largest interval of constancy containing 55 is $[-8, 55]$, and the closed form gives $\lceil(-9-55)/64\rceil + 4 = 3$. The corollary is therefore stated on the range Definition 8 actually covers. By Definition 7 nothing below $\ell = 13$ is ever reached, so the restriction costs nothing.

The single step of $\mathsf{cost}$ between $\ell = 55$ and $\ell = 56$ is the entire basis of the attack. 

#### 1.1.5 Two leakage models

The results of §1.3 are stated in a model in which decryption returns a measurement of its running time alongside its verdict. This extension is necessary: Section 3 shows that without it the scheme is provably secure and no adversary of the kind built in §1.2 can exist.

![Noiseless Model](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/model-a.svg)

**Model A (noiseless).** The decryption oracle returns the pair $\big(\mathsf{Dec}_K(\mathrm{HDR}, C; \sigma),\; \mathsf{cost}(\lambda(P))\big)$, and returns $\varnothing$ in the second component for a record rejected at step 1 of Definition 4. Two things are being idealised here and both are stated as hypotheses rather than left implicit. First, the second component is a *count*, not a time; Model B is what converts it. Second, the model presumes that all per-query work other than the MAC is equal across the queries being compared. Equal ciphertext length equalises the number $n$ of block-cipher inversions, but *not* the padding scan, whose cost depends on the padding value $p$ and varies at fixed length; Hypothesis 6 (constant-time comparison) is what removes that residual term, leaving the MAC as the sole plaintext-dependent cost. Results proved in Model A therefore hold for adversaries all of whose decryption queries have equal ciphertext length, against a receiver satisfying Hypothesis 6. The adversary of Section 2 meets the length restriction, every query being four non-IV blocks.

![Noisy Model](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/model-b.svg)

**Model B (noisy).** The oracle returns $\big(\mathsf{Dec}_K(\mathrm{HDR}, C; \sigma),\; \tau\big)$ with $\tau = c_0 \cdot \mathsf{cost}(\lambda(P)) + \eta$, where $c_0 > 0$ is the cost of one compression-function evaluation and $\eta$ is drawn independently per query from a fixed, key-independent, mean-zero distribution assumed sub-Gaussian with parameter $\sigma_{\!\eta}$. The adversary is given $c_0$ and $\sigma_{\!\eta}$. Model B abstracts network jitter, and inherits Model A's equal-length restriction. Model A is its limit as $\sigma_{\!\eta}/c_0 \to 0$; Section 3 quantifies the passage between them, and should be compared against the sample-complexity analysis already present at [[LT, §7, pp. 15–16]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) as well as the measurements of [[LT, §5]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf).

#### 1.1.6 The session model

TLS treats every decryption failure as fatal: an alert is sent and the connection is torn down with its keys discarded [[LT, §2]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf). A single decryption query therefore destroys the session in which it is made, and an adversary needing many queries needs many sessions.

![Multi Session](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/multi-session.svg)

**Definition 11 (multi-session experiment).** The adversary interacts with $q$ sessions. Each session $s \in [1,q]$ is initialised independently by $\mathsf{Gen}$, so keys, IVs and states are fresh and mutually independent. Each session uses the same padding parameter $j$ and encrypts the same challenge record $R^\ast$, of a length fixed by the record distribution, at the same record index $k \ge 1$; the adversary receives all $q$ resulting ciphertexts. The adversary may make at most one decryption query per session, and may not query the ciphertext it was given for that session.

Three of these conditions are more than bookkeeping. Fixing $j$ and $|R^\ast|$ is what makes "the same block index" pick out the same thing in every session. Requiring $k \ge 1$ and forbidding the challenge ciphertext is what keeps the experiment non-trivial: at $k = 0$ the receiver's counter still matches the sender's, so replaying the challenge into its own session's oracle would decrypt it and hand back $R^\ast$ in the clear.

The hypothesis that the same record recurs at the same position across sessions is the strongest assumption in this development, and is carried explicitly into the statement of every result that uses it. It is the model of [[CHVV03]](https://www.scilit.com/publications/7a4b73573841857d9102de26df89dbd3); [[LT, §1.1, p. 2]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) motivates it by the behaviour of clients that reconnect and retransmit credentials automatically, and [[LT, §4.2]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) adopts it by reference. The DTLS analogue of the attack dispenses with it entirely: DTLS errors are non-fatal, so the attack runs within a single session and the construction is otherwise identical [[LT, §4.4]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf).

#### 1.1.7 The plaintext-recovery game

![Plaintext-recovery experiment](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/pr-experiment.svg)

**Definition 12.** For a scheme $\Pi$, an adversary $\mathcal{A}$, a record distribution $\mathcal{M}$ of fixed length at least $b$ (so that a whole block can lie within a record) and a leakage model $X \in \{\mathrm{A}, \mathrm{B}\}$, the experiment $\mathbf{Exp}^{\mathrm{PR}\text{-}X}_{\Pi, \mathcal{A}, \mathcal{M}}(q)$ is:

1. Sample $R^\ast \leftarrow \mathcal{M}$ and initialise $q$ independent sessions as in Definition 11.
2. In each session encrypt $R^\ast$ at index $k$ and give $\mathcal{A}$ all $q$ ciphertexts.
3. Fix a block index $m$ such that the $m$-th block of $\mathsf{Encode}(R^\ast, T; j)$ lies wholly within $R^\ast$, and let $P^\ast$ be that block. Each session has its own target ciphertext block $C^\ast_s$, namely the $m$-th non-IV block of that session's ciphertext.
4. Give $\mathcal{A}$ the model-$X$ decryption oracle, subject to Definition 11's restrictions.
5. $\mathcal{A}$ outputs $\hat{P} \in \mathbb{B}^{b}$ and wins iff $\hat{P} = P^\ast$.

Define $\mathbf{Adv}^{\mathrm{PR}\text{-}X}_{\Pi, \mathcal{M}}(\mathcal{A}, q) = \Pr\big[\mathcal{A} \text{ wins}\big]$.

The restriction in step 3 is necessary. Keys are independent across sessions, so the tag $T$ differs in every session; any block of the encoding containing a tag or padding byte is therefore session-dependent, and "$P^\ast$" would not name a single object. Confining $m$ to a block wholly inside $R^\ast$ makes $P^\ast$ well defined and equal to a block of the record itself. Note that the *final* block is never admissible: $|T \,\|\, \langle p\rangle^{p+1}| = t + p + 1 \ge t+1 > b$ for every $t \in \{16,20,32\}$ with $b = 16$, so the last block of an encoding never contains record bytes at all.

Unlike an indistinguishability advantage this quantity is not normalised against a baseline of $1/2$: guessing achieves $2^{-8b}$, while Theorem 2 drives it to exactly 1 in Model A, and Theorem 3 to $1 - \epsilon$ in the noisy model.

![Distinguishing experiment](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/ind-experiment.svg)

**Definition 13.** The distinguishing experiment $\mathbf{Exp}^{\mathrm{IND}\text{-}X}_{\Pi, \mathcal{A}}$ runs in a single session. $\mathcal{A}$ submits $(M_0, M_1)$ with $|M_0| = |M_1|$, receives an encryption of $M_d$ for uniform $d$, may make one decryption query other than the challenge ciphertext, and outputs $\hat{d}$; its advantage is $\big|2\Pr[\hat d = d] - 1\big|$. The length restriction prevents a trivial win, and the single-query limit is the same consequence of fatal alerts as in Definition 11.


### 1.2. The cryptographic adversary

![Distinguishing Adversary](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/dist-adversary.svg)

$\mathcal{A}_{\mathrm{dist}}$ submits the pair $M_0 = \langle a \rangle^{32} \,\|\, \langle \texttt{0xFF} \rangle^{256}$ and $M_1 = \langle a \rangle^{287} \,\|\, \texttt{0x00}$ for an arbitrary byte $a$; both have length 288, so the length restriction of Definition 13 is met and both encode into 18 blocks with $T \,\|\, \mathit{pad}$ occupying whole blocks disjoint from the message. On receiving the challenge $\mathrm{HDR} \,\|\, C$ it forms $C'$ by keeping the IV and truncating the non-IV part of $C$ to its first 288 bytes, thereby discarding the blocks carrying $T \,\|\, \mathit{pad}$, and it makes its one decryption query on $\mathrm{HDR} \,\|\, C'$. It outputs $\hat d = 0$ if the reported count is 4, and $\hat d = 1$ otherwise.

The two outcomes are separated by the leakage. If $d = 0$ the truncated plaintext ends in the well-formed pattern $\langle \texttt{0xFF} \rangle^{256}$, so 256 bytes are stripped, 32 remain, and $\lambda = 13 + (32 - 20) = 25$, whence $\mathsf{cost} = 4$. If $d = 1$ it ends in the well-formed single byte $\texttt{0x00}$, so one byte is stripped, 287 remain, and $\lambda = 13 + (287 - 20) = 280$, whence $\mathsf{cost} = 8$. The gap of four compression evaluations is the signal; §1.3 turns it into the advantage bound of Theorem 1.

#### 1.2.1 Attack geometry

![Attack geometry](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/attack-geometry.svg)

Fix a session and let $C^\ast$ be its target ciphertext block, $C'$ the block preceding it in that session's ciphertext (the IV if the target is the first non-IV block). By Definition 4, $P^\ast = D_{K_e}(C^\ast) \oplus C'$ is the target plaintext block, and by Definition 12 it lies wholly within $R^\ast$ and is therefore the same string in every session, although $C^\ast$ and $C'$ are not.

For a mask $\Delta \in \mathbb{B}^{b}$ the adversary assembles the four-block forgery

$$C^{\mathrm{att}}(\Delta) = \mathrm{HDR} \,\|\, C_0 \,\|\, C_1 \,\|\, C_2 \,\|\, (C' \oplus \Delta) \,\|\, C^\ast,$$

where $C_0$ is any IV and $C_1, C_2$ are arbitrary blocks. It has four non-IV blocks, so $\ell_P = 64$ and step 1 of Definition 4 admits it. Writing $P = P_1 \,\|\, P_2 \,\|\, P_3 \,\|\, P_4$ for its decryption,

$$P_4 = D_{K_e}(C^\ast) \oplus (C' \oplus \Delta) = P^\ast \oplus \Delta,$$

so the adversary controls the trailing block of the decrypted plaintext, byte for byte, by choice of $\Delta$, while never learning $K_e$. The block $P_3 = D_{K_e}(C' \oplus \Delta) \oplus C_2$ is not controlled; it enters the padding check only when a well-formed run exceeds the 16 bytes of $P_4$, and Section 3 (Lemma 4) shows the disambiguation of Section 2 breaks every such run regardless of $P_3$.

#### 1.2.2 The three cases

![The three cases](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/three-cases.svg)

With $\ell_P = 64$, $t = 20$ and $h = 13$, the value of $\mathsf{cost}(\lambda(P))$ observed for $C^{\mathrm{att}}(\Delta)$ is determined by the trailing bytes of $P_4$, and exactly one of the following holds.

- *Case 1.* $P_4$ ends in $\texttt{0x00}$: well-formed padding with $p = 0$, one byte stripped, $|R| = 43$, $\lambda = 56$, $\mathsf{cost} = 5$.
- *Case 2.* $P_4$ ends in well-formed padding of length $p + 1 \ge 2$, i.e. $p \in [1, 43]$: at least two bytes stripped, $|R| = 43 - p \le 42$, $\lambda = 56 - p \le 55$, $\mathsf{cost} = 4$.
- *Case 3.* $P_4$ ends in any other pattern: not well-formed, the else-branch of step 5 applies, $|R| = 44$, $\lambda = 57$, $\mathsf{cost} = 5$.

The range $p \in [1,43]$ in Case 2 is forced by the underflow test of step 4: at $\ell_P = 64$ a value $p \ge 44$ leaves no room for the tag, so it falls into Case 3 rather than Case 2. The three cases therefore produce only two distinct counts (4 for Case 2 and 5 for Cases 1 and 3), and Cases 1 and 3 are indistinguishable at every admissible ciphertext length. This is sufficient, because the adversary only ever needs to know whether it is in Case 2.

#### 1.2.3 The adversary $\mathcal{A}_{\mathrm{PR}}$

![The recovery phases](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/recovery-phases.svg)

The adversary uses one primitive. $\mathsf{Probe}(\Delta)$ consumes one fresh session, assembles $C^{\mathrm{att}}(\Delta)$ from that session's target and predecessor blocks, makes the single permitted decryption query, and returns $\mathsf{true}$ iff the reported count is 4. This is precisely the test "$P^\ast \oplus \Delta$ ends in well-formed padding of length at least two", it realises this padding-checking oracle exactly.

**Phase 1 (last two bytes).** With $\Delta[0 \mathinner{.\,.} 13] = \langle \texttt{0x00} \rangle^{14}$ fixed, enumerate $(\Delta[14], \Delta[15])$ over $\mathbb{B}^2$ until $\mathsf{Probe}(\Delta)$ returns $\mathsf{true}$. The intended success sets $P_4$ to end in $\texttt{0x01}\,\|\,\texttt{0x01}$, i.e. $\Delta[14] = P^\ast[14] \oplus \texttt{0x01}$ and $\Delta[15] = P^\ast[15] \oplus \texttt{0x01}$; at most $2^{16}$ probes are used.

**Phase 1b (disambiguation).** A $\mathsf{true}$ in Phase 1 can also come from a well-formed pattern longer than two bytes. On each such $\mathsf{true}$, re-probe with $\Delta$ altered only in byte 13. A length-2 pattern is unaffected and still returns $\mathsf{true}$; any longer pattern is destroyed and returns $\mathsf{false}$. This distinguishes the intended event with at most 43 additional probes (one per admissible padding length $p \in [1,43]$); Section 3 (Lemma 4) shows the resolution is exact, so no residual error remains.

**Phase 2 (remaining bytes).** For $i = 2, 3, \dots, 15$, with $P^\ast[16-i \mathinner{.\,.} 15]$ already recovered, set $\Delta[j] = P^\ast[j] \oplus i$ for each $j \in [16-i, 15]$ (forcing those bytes of $P_4$ to $i$) and enumerate $\Delta[15-i]$ over $\mathbb{B}$. Exactly one value makes $P_4$ end in the well-formed pattern $\langle i \rangle^{i+1}$, returning $\mathsf{true}$, and then $P^\ast[15-i] = \Delta[15-i] \oplus i$. Each position costs at most $2^8$ probes, and this phase is the padding-oracle recovery of [[V02]](https://infoscience.epfl.ch/entities/publication/60268d2e-9c20-4d4f-9c85-6fff38c5454f/conferencedetails).

**Algorithm 1.** The adversary in full. Each call to $\mathsf{Probe}$ opens a fresh session $s$, whose target block $C^\ast_s$, predecessor block $C'_s$ and Model A decryption oracle $\mathcal{O}_s$ it uses once; $C_0, C_1, C_2$ are arbitrary blocks, and $e_{13} \in \mathbb{B}^b$ is the mask equal to $\texttt{0xFF}$ in byte 13 and zero elsewhere. The conjunction is evaluated left to right, so the Phase 1b probe is spent only on a Phase 1 hit.

$$
\begin{array}{l}
\underline{\mathsf{Probe}(\Delta)} \\
\quad s \leftarrow \text{fresh session} \\
\quad C^{\mathrm{att}} \leftarrow \mathrm{HDR} \,\|\, C_0 \,\|\, C_1 \,\|\, C_2 \,\|\, (C'_s \oplus \Delta) \,\|\, C^\ast_s \\
\quad (\cdot, c) \leftarrow \mathcal{O}_s(C^{\mathrm{att}}) \\
\quad \textbf{return } [\, c = 4 \,]
\end{array}
$$

$$
\begin{array}{l}
\underline{\mathcal{A}_{\mathrm{PR}}} \\
\textbf{for } (\delta_{14}, \delta_{15}) \in \mathbb{B}^2 \textbf{ do} \\
\quad \Delta \leftarrow \langle \texttt{0x00} \rangle^{14} \,\|\, \delta_{14} \,\|\, \delta_{15} \\
\quad \textbf{if } \mathsf{Probe}(\Delta) \wedge \mathsf{Probe}(\Delta \oplus e_{13}) \textbf{ then break} \\
\hat P[14] \leftarrow \delta_{14} \oplus \texttt{0x01}; \ \hat P[15] \leftarrow \delta_{15} \oplus \texttt{0x01} \\
\textbf{for } i = 2, \dots, 15 \textbf{ do} \\
\quad \Delta[16-i \mathinner{.\,.} 15] \leftarrow \hat P[16-i \mathinner{.\,.} 15] \oplus \langle i \rangle^{i} \\
\quad \textbf{for } g \in \mathbb{B} \textbf{ do} \\
\quad \quad \Delta[15-i] \leftarrow g \\
\quad \quad \textbf{if } \mathsf{Probe}(\Delta) \textbf{ then break} \\
\quad \hat P[15-i] \leftarrow g \oplus i \\
\textbf{return } \hat P
\end{array}
$$

The algorithm makes the adversary's interface explicit: per session it sees two ciphertext blocks and one bit of leakage, and it never holds key material.

The worst-case probe count, and hence session count, is $2^{16} + 43 + 14 \cdot 2^8$ (enumeration, disambiguation, and Phase 2); the $2^{16}$ term dominates. [[LT, p. 8]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) gives the enumeration and Phase-2 terms; the disambiguation term is made explicit here.


If one of the last two bytes of $P^\ast$ is known, Phase 1 collapses from $2^{16}$ to $2^8$ by fixing the known byte and enumerating the other, giving $15 L \cdot 2^8$ sessions for a full block at $L$ trials per position. If the record bytes are drawn from a restricted alphabet (for instance base64-encoded credentials, at 64 values per byte), Phase 2's enumeration shortens to $2^6$ per position. And in the browser setting of [[LT, §4.2]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf), where the target is an HTTP cookie, malware in the victim's browser opens the sessions itself and adjusts request lengths so that each target block holds a single unknown byte, which combined with the partially-known-plaintext variant reaches roughly $2^{13}$ sessions per byte at the measured $L = 2^7$. These are corollaries of the same adversary and do not alter the correctness argument of §1.3.

### 1.3. The plaintext recovery

![Lemma 1 as a decision tree](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/lemma1-tree.svg)

**Lemma 1 (encoding length)** For every key and every mask $\Delta$, the decryption of $C^{\mathrm{att}}(\Delta)$ under Definition 4 reaches step 5 and computes an HMAC input length $\lambda$ equal to 56 if $P_4$ ends in $\texttt{0x00}$ (Case 1), at most 55 if $P_4$ ends in well-formed padding of length at least two (Case 2), and 57 otherwise (Case 3).
- **Hypotheses.** The instantiation $b = 16$, $t = 20$, $h = 13$; the encoding and decryption of Definitions 1 and 4; Hypothesis 5 (so that the underflow branch is reached, not the skip branch).
- **Uses.** Definition 4, Definition 7, the case ranges of Section 2.

![Leakage separation](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/lemma2-separation.svg)

**Lemma 2 (leakage separation)** Under Model A, the count reported for $C^{\mathrm{att}}(\Delta)$ is 4 in Case 2 and 5 in Cases 1 and 3. Consequently the oracle yields exactly two distinguishable values, and Cases 1 and 3 are timing-identical; moreover no admissible ciphertext length separates Cases 1 and 3.
- **Hypotheses.** Lemma 1; the ceiling convention of the standing conventions; the hypotheses of Proposition 9 (so $H$ has a 64-byte block and $d \le 55$).
- **Uses.** Lemma 1, Proposition 9, Corollary 10.

**Remark (why $h = 13$).** Under the counterfactual $h = 12$, Case 1 would give $\lambda = 55$ and hence count 4, merging with Case 2; a single $\texttt{0x00}$ would then suffice and the recovery of Section 2 would cost $2^8$ rather than $2^{16}$ for the first two bytes. This is the sense in which the header length is "lucky"; it is proved as part of Lemma 2.

**Remark (other tag lengths).** Lemmas 1 and 2 are specific to $t = 20$. In general Case 2 gives $\lambda = h + \ell_P - t - 1 - p$ and Cases 1 and 3 give $\lambda = h + \ell_P - t - 1$ and $h + \ell_P - t$. With $t = 16$ and $\ell_P = 64$, Cases 1 and 3 give $\lambda \in \{60, 61\}$ and count 5, but Case 2 reaches $\lambda \le 55$ only when $p \ge 5$: the fast case needs padding of length at least 6, and Phase 1 must enumerate six bytes, $2^{48}$ probes in the worst case. With $t = 32$ and $\ell_P = 64$, every case has $\lambda \le 45$ and count 4, so four blocks give no signal at all; at five blocks ($\ell_P = 80$) the values of $t = 16$ reappear, with the same threshold of length 6. For both tag lengths only the partially-known-plaintext variants of §1.2.3 remain practical [[LT, §4.3]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf).

![Probe as a padding-checking oracle](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/lemma3-oracle.svg)

**Lemma 3 (Probe is a perfect padding-checking oracle)** In Model A, for every session key and every mask $\Delta$, $\mathsf{Probe}(\Delta)$ returns $\mathsf{true}$ if and only if $P^\ast \oplus \Delta$ ends in well-formed padding of length at least two. The identity is exact and deterministic; no idealisation, and no computational assumption, is involved.
- **Hypotheses.** Lemma 2 (the cost identity); the CBC relation $P_4 = P^\ast \oplus \Delta$ of Section 2; equal ciphertext length across queries (Model A, satisfied because every $C^{\mathrm{att}}(\Delta)$ has four non-IV blocks and so reaches step 5); Hypothesis 5.
- **Uses.** Lemma 2.

**Remark (verdict-independence).** The count $\mathsf{cost}(\lambda(P))$ is fixed at step 5/6 of Definition 4 and returned regardless of whether the MAC verifies at step 7, so it is independent of the MAC key. This is exactly why the attack defeats the RFC countermeasure of Section 1: that countermeasure makes the *verdict* uninformative by always checking a MAC, but the *time* of that check still leaks $\lambda$. In consequence the MAC's unforgeability plays no role in the recovery (in contrast to the verdict-based padding oracles of [[V02]](https://infoscience.epfl.ch/entities/publication/60268d2e-9c20-4d4f-9c85-6fff38c5454f/conferencedetails) and [[CHVV03]](https://www.scilit.com/publications/7a4b73573841857d9102de26df89dbd3), where it is essential) and re-enters only in the positive result of Section 3.

#### 1.3.1 Phase correctness and the recovery theorems

![Phase 1b disambiguation](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/lemma4-disambiguation.svg)

**Lemma 4 (Phase 1 correctness, exact).** Phases 1 and 1b of Section 2 output $P^\ast[14]$ and $P^\ast[15]$ exactly, within $2^{16} + 43$ probes, with no probability of error.
- *Hypotheses:* Lemma 3. 
- *Uses:* Lemma 3.

The exactness rests on one structural fact. A well-formed run of length $\ell$ occupies the last $\ell$ bytes of the decrypted plaintext, so it covers byte 13 of $P_4$ if and only if $\ell \ge 3$. The unique length-2 run is therefore the only Case-2 configuration reachable in Phase 1 that does not involve byte 13. Phase 1b perturbs byte 13 and re-probes: a length-2 run is untouched and survives, while every longer run is destroyed, including a run extending into the uncontrolled block $P_3$, since such a run has $\ell > 16 \ge 3$ and so also covers byte 13. The length-2 mask $\Delta[14] = P^\ast[14] \oplus \texttt{0x01}$, $\Delta[15] = P^\ast[15] \oplus \texttt{0x01}$ always exists and always passes Phase 1b, and any earlier hit in enumeration order is a longer run and is rejected. No appeal to the distribution of $P_3$ is needed; the separation is deterministic.

![Phase 2 uniqueness](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/lemma5-uniqueness.svg)

**Lemma 5 (Phase 2 correctness, exact).** Conditioned on correct recovery of $P^\ast[16-i \mathinner{.\,.} 15]$, iteration $i$ of Phase 2 outputs $P^\ast[15-i]$ exactly, within $2^8$ probes.
- *Hypotheses:* Lemma 3. 
- *Uses:* Lemma 3.

Fixing the last byte of $P_4$ to $i$ pins the padding length to $i+1 \le 16$, so the checked pattern $\langle i \rangle^{i+1}$ lies wholly within the controlled block $P_4$; exactly one value of $\Delta[15-i]$ completes it, and no block other than $P_4$ enters. Phase 2 therefore needs neither disambiguation nor any appeal to $P_3$.

![Theorem 1: advantage exactly 1](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/theorem1-advantage.svg)

**Theorem 1 (distinguishing).** In Model A the adversary $\mathcal{A}_{\mathrm{dist}}$ of Section 2 satisfies $\mathbf{Adv}^{\mathrm{IND}\text{-}\mathrm{A}}_{\Pi}(\mathcal{A}_{\mathrm{dist}}) = 1$ with a single decryption query.
- *Hypotheses:* Definition 13; the case arithmetic of Section 2 ($\lambda = 25$ against $280$, count 4 against 8). 
- *Uses:*  Section 2. 

The query is a genuine truncation of the challenge ciphertext, so it decrypts deterministically and the observed count is a deterministic function of $d$; this is an equality, not a bound, and it uses neither Lemma 3 nor any computational assumption.

![Theorem 2: composition and accounting](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/theorem2-composition.svg)

**Theorem 2 (plaintext recovery, main).** In Model A, under the multi-session interface of Section 1 with the target block $P^\ast$ lying wholly within $R^\ast$ and the challenge ciphertext excluded from queries, the adversary $\mathcal{A}_{\mathrm{PR}}$ recovers $P^\ast$ with

$$\mathbf{Adv}^{\mathrm{PR}\text{-}\mathrm{A}}_{\Pi, \mathcal{M}}(\mathcal{A}_{\mathrm{PR}}, q) = 1,$$

consuming $q \le 2^{16} + 43 + 14\cdot 2^8$ sessions and one decryption query each.
- *Hypotheses:* same record at the same index across sessions, with fixed $|R^\ast|$ ; $k \ge 1$, $|R^\ast| \ge b$, and challenge excluded ; Hypothesis 5. *
- Uses:* Lemma 3, Lemma 4, Lemma 5.

The advantage is exactly 1, with no computational assumption: Lemma 3 turns the leakage into a perfect padding oracle, and Lemmas 4 and 5 recover the sixteen bytes deterministically from it.

**Remark (where the assumptions went).** The PRP and SUF-CMA assumptions of Section 1 appear in neither Theorem 1 nor Theorem 2. The noiseless leakage oracle is information-theoretically perfect, so the recovery is unconditional. The assumptions are needed only for the converse, which shows that *without* the leakage the same scheme is secure. This is the precise content of the claim that the result is about the side channel and not about the cipher: the very assumptions under which MEE-TLS-CBC is provably secure are untouched by the attack, and the attack succeeds regardless.

#### 1.3.2 Theorem 3 (the noisy model)

![Theorem 3: the noisy model](https://lattice-walker.github.io/CipherOps/articles/post-quantum-algorithms/TLS-1-2-CBC-mode/illustrations/theorem3-noise.svg)

In Model B with per-query mean-zero sub-Gaussian noise of parameter $\sigma_{\!\eta}$, running $\mathsf{Probe}$ $L$ times per mask and thresholding the sample mean at $\tfrac{9}{2} c_0$ recovers $P^\ast$ with probability at least $1 - \epsilon$ provided

$$L \;\ge\; \frac{8\,\sigma_{\!\eta}^2}{c_0^2} \cdot \ln\frac{2M}{\epsilon}, \qquad M = 2^{16} + 43 + 14\cdot 2^8,$$

at a total cost of $L \cdot q$ sessions with $q$ as in Theorem 2. (Under a heavier-tailed noise model than sub-Gaussian, replace the mean by a median-of-means estimator; the $\sigma_{\!\eta}^2/c_0^2$ scaling is unchanged, and this is what the median-based processing of [[LT, §5]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) approximates on its skewed data.)

At concrete noise levels the bound gives the following repetition counts $L$ per mask, and the corresponding worst-case total $L \cdot M$ of sessions.

| $\sigma_{\!\eta}/c_0$ | $L$ at $\epsilon = 0.1$ | $L$ at $\epsilon = 0.01$ | $L \cdot M$ at $\epsilon = 0.1$ |
|---|---|---|---|
| 1 | 114 | 132 | $\approx 7.9 \cdot 10^{6}$ |
| 3 | 1 019 | 1 184 | $\approx 7.0 \cdot 10^{7}$ |
| 10 | 11 312 | 13 155 | $\approx 7.8 \cdot 10^{8}$ |
| 20 | 45 248 | 52 617 | $\approx 3.1 \cdot 10^{9}$ |

$L$ grows quadratically in $\sigma_{\!\eta}/c_0$ and only logarithmically in $1/\epsilon$, so the noise level, not the target error, drives the cost.

- **Hypotheses.** Theorem 2 (the underlying deterministic signal); the noise model of Section 1 (per-query independence, mean zero, sub-Gaussian); equal ciphertext length across queries.
- **Uses.** Theorem 2, a concentration bound for the mean of sub-Gaussian samples, a union bound over the at most $M = 2^{16} + 43 + 14\cdot 2^8$ masks.

**Remark.** No computational assumption enters here either: the signal separating Case 2 (mean $4c_0$) from Cases 1 and 3 (mean $5c_0$) is deterministic, and $L$ must overcome only the noise, not the cipher. This is the sole result in §1.3 carrying a failure probability, and the only one [[LT]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) does not underwrite with a bound; the resulting $L$ should be compared against the measured $L = 2^7$ of [[LT, §5]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) and the sample-complexity discussion of [[LT, §7, pp. 15–16]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf).

**Proposition 6 (the leakage model is necessary)** In  model, where the decryption oracle returns only its verdict in $\{R, \bot\}$ and no count, MEE-TLS-CBC with the components of Section 1 achieves Length-Hiding Authenticated Encryption, and consequently no efficient adversary attains non-negligible $\mathbf{Adv}^{\mathrm{PR}}$. Hence the leakage component of Model A is necessary: Theorem 2 fails against a leakage-free oracle.
- **Hypotheses.** The positive result of [PRS11](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20) for MEE-TLS-CBC; the identification of its hypotheses with the PRP and SUF-CMA assumptions of Section 1 (this identification must be checked against [PRS11](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20) directly, as flagged in the ledger, since [[LT]](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) states them only informally).
- **Uses.** [PRS11](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20); the definitions of Section 1.

### 1.4. Proofs

The proofs are given in dependency order.

#### Proof of Lemma 1 (encoding length)

The ciphertext $C^{\mathrm{att}}(\Delta)$ has four non-IV blocks, so $\ell_P = 64$, which passes step 1 of Definition 4 ($64$ is a positive multiple of $b$ and $64 \ge t+1 = 21$); decryption reaches step 5. Write $p = P_4[15]$. By Definition 4 step 4 the padding is well-formed iff $64 \ge p + 1 + t$ (that is, $p \le 43$) and the last $p+1$ bytes of $P$ all equal $p$.

- *Case 1*, $p = 0$: well-formed ($0 \le 43$, last byte $= 0$), so $r = 64 - 0 - 1 - 20 = 43$ and $\lambda = h + r = 13 + 43 = 56$.
- *Case 2*, well-formed with $p \in [1,43]$: $r = 64 - p - 1 - 20 = 43 - p \le 42$, so $\lambda = 56 - p \le 55$.
- *Case 3*, not well-formed: step 5's else-branch gives $r = 64 - 20 = 44$ and $\lambda = 57$.

For $p \ge 44$ we have $p + 1 + t = p + 21 > 64$, so the length test fails and the configuration is Case 3, not Case 2; this is why Case 2 is confined to $p \in [1,43]$. The three cases are exhaustive in $p = P_4[15]$. $\square$

#### Proof of Lemma 2 (leakage separation)

$H = \mathrm{SHA\text{-}1}$ has a 64-byte block, an 8-byte length field and digest length $d = 20 \le 55$, and $|K_a| \le 64$, so Proposition 9 applies and $\mathsf{cost}(\ell) = \lceil (\ell - 55)/64 \rceil + 4$. By Corollary 10, $\mathsf{cost} = 4$ on $[0,55]$ and $\mathsf{cost} = 5$ on $[56,119]$. Substituting Lemma 1: Case 2 has $\lambda \le 55$, so $\mathsf{cost} = 4$; Cases 1 and 3 have $\lambda \in \{56, 57\} \subseteq [56,119]$, so $\mathsf{cost} = 5$. Thus the oracle reports exactly two values, $4$ and $5$.

For the second clause, Cases 1 and 3 have $\lambda_1 = h + \ell_P - t - 1$ and $\lambda_3 = h + \ell_P - t = \lambda_1 + 1$. As $\mathsf{cost}$ increases by one exactly when its argument crosses $55 \pmod{64}$, $\mathsf{cost}(\lambda_1) \ne \mathsf{cost}(\lambda_3)$ would require $\lambda_1 \equiv 55 \pmod{64}$, i.e. $\ell_P \equiv 55 + t + 1 - h = 63 \pmod{64}$. But $\ell_P = 16n$ is even and $63$ is odd, so no admissible $\ell_P$ separates Cases 1 and 3. $\square$

The $h = 12$ remark of Section 3 follows by the same substitution: with $h = 12$, Case 1 gives $\lambda = 55$, hence $\mathsf{cost} = 4$, so Case 1 would join Case 2 in the fast bucket and a single $\texttt{0x00}$ would suffice, collapsing Phase 1 to $2^8$.

#### Proof of Lemma 3 (perfect oracle)

By construction, the penultimate block of $C^{\mathrm{att}}(\Delta)$ is $C' \oplus \Delta$ and the last is $C^\ast$, so under Definition 4,

$$P_4 = D_{K_e}(C^\ast) \oplus (C' \oplus \Delta) = \big(D_{K_e}(C^\ast) \oplus C'\big) \oplus \Delta = P^\ast \oplus \Delta,$$

using $P^\ast = D_{K_e}(C^\ast) \oplus C'$. This is an exact identity in the real scheme; no idealisation is used. Every $C^{\mathrm{att}}(\Delta)$ has four non-IV blocks, so all queries have equal ciphertext length and each reaches step 5, meeting the Model A restriction. In Model A the reported count is $\mathsf{cost}(\lambda(P))$, and by Lemma 2 this equals $4$ iff the decryption is Case 2, i.e. iff $P_4 = P^\ast \oplus \Delta$ ends in well-formed padding of length $\ge 2$. Hence $\mathsf{Probe}(\Delta) = [\text{count} = 4]$ equals that predicate exactly and deterministically.

The count is computed at step 5/6 from $P$ alone and is returned before, and independently of, the verdict at step 7; it therefore does not depend on $K_a$ or on whether any forgery verifies. No PRP or MAC assumption is invoked. $\square$

#### Proof of Lemma 4 (Phase 1 exact)

Let $(a,b) = (P^\ast[14], P^\ast[15])$. Throughout Phase 1, $\Delta[0 \mathinner{.\,.} 13] = 0$, so $P_4[j] = P^\ast[j]$ for $j \le 13$, and only $P_4[14], P_4[15]$ vary with the probe.

*The intended mask is accepted.* At $\Delta^\ast$ with $\Delta^\ast[14] = a \oplus \texttt{0x01}$, $\Delta^\ast[15] = b \oplus \texttt{0x01}$, we get $P_4[14] = P_4[15] = \texttt{0x01}$, so $p = 1$ and the last two bytes both equal $1$: well-formed, length 2, Case 2, so $\mathsf{Probe}(\Delta^\ast) = \mathsf{true}$ by Lemma 3. In Phase 1b, byte 13 of $\Delta^\ast$ is flipped; since $p = 1$ the well-formedness test inspects only bytes 14 and 15, which are unchanged, so the re-probe is still Case 2 and $\Delta^\ast$ is accepted, yielding $P^\ast[14] = \Delta^\ast[14] \oplus \texttt{0x01} = a$ and $P^\ast[15] = b$.

*No other mask is accepted.* Suppose $\Delta$ is accepted, so both probes return $\mathsf{true}$. The first says $P_4$ ends in a well-formed run of some length $p+1 \ge 2$. If $p \ge 2$, the run occupies bytes $[15-p, 15]$ of $P_4$ with $15 - p \le 13$, so it covers byte 13 — and if $p \ge 16$ the run additionally reaches into $P_3$, but still covers byte 13, since $15 - p < 0 \le 13$. Phase 1b flips byte 13 while leaving $P_4[15] = p$ unchanged, so the receiver still reads $\mathit{padlen} = p$ but now finds $P_4[13] \ne p$; the run fails and the configuration becomes Case 3. Hence the re-probe returns $\mathsf{false}$ and $\Delta$ is not accepted — contradiction. So $p = 1$, forcing $P_4[14] = P_4[15] = 1$, i.e. $\Delta = \Delta^\ast$. The accepted mask is unique and correct.

*Probe count.* Enumeration visits at most $2^{16}$ masks. A disambiguation probe is spent only on a Case-2 hit, and for each padding length $p \in [1,43]$ the hit mask is forced ($P_4[14] = P_4[15] = p$ determines $\Delta[14], \Delta[15]$ uniquely), so at most 43 hits occur, hence at most 43 disambiguation probes. Total $\le 2^{16} + 43$. $\square$

#### Proof of Lemma 5 (Phase 2 exact)

Fix iteration $i \in [2,15]$ with $P^\ast[16-i \mathinner{.\,.} 15]$ known. Setting $\Delta[j] = P^\ast[j] \oplus i$ for $j \in [16-i, 15]$ makes $P_4[j] = i$ there; in particular $P_4[15] = i$, so the receiver reads $\mathit{padlen} = i$ and tests whether bytes $[15-i, 15]$ all equal $i$. Bytes $[16-i, 15]$ already equal $i$, so the test passes iff $P_4[15-i] = i$, i.e. iff $\Delta[15-i] = P^\ast[15-i] \oplus i$ — a unique value among the 256 enumerated. At that value the run has length $i+1 \in [3,16]$, well-formed (since $i + 1 + 20 \le 36 \le 64$) and $\ge 2$, so $\mathsf{Probe} = \mathsf{true}$ by Lemma 3, and $P^\ast[15-i] = \Delta[15-i] \oplus i$. Because $i + 1 \le 16$ the run lies wholly in $P_4$, so no block other than $P_4$ enters and no disambiguation is needed. At most $2^8$ probes. $\square$

#### Proof of Theorem 1 (distinguishing)

$\mathcal{A}_{\mathrm{dist}}$ submits the 288-byte messages of Section 2 and receives $C = \mathsf{Enc}(M_d)$. Since $|M_d| = 288 = 18b$, the encoding $M_d \,\|\, T \,\|\, \mathit{pad}$ places $T \,\|\, \mathit{pad}$ in blocks beyond the first 18, so truncating the non-IV part of $C$ to 288 bytes and keeping the IV yields $C'$ whose decryption is exactly $P' = M_d$. For $d = 0$, $P'$ ends in $\langle \texttt{0xFF} \rangle^{256}$: well-formed, $p = 255$, $r = 288 - 256 - 20 = 12$, $\lambda = 25$, count 4. For $d = 1$, $P'$ ends in $\texttt{0x00}$: $p = 0$, $r = 288 - 1 - 20 = 267$, $\lambda = 280$, count 8. The observed count is a deterministic function of $d$, and $\mathcal{A}_{\mathrm{dist}}$ outputs $\hat d = 0$ iff it is 4, so $\hat d = d$ always and the advantage is $|2 \cdot 1 - 1| = 1$. The single query is not the challenge ciphertext (it is a truncation), meeting Definition 13. $\square$

#### Proof of Theorem 2 (plaintext recovery)

The hypotheses make $P^\ast$ well defined and session-independent: $|R^\ast| \ge b$ and $P^\ast$ wholly within $R^\ast$ give a target block of record bytes, which is identical across sessions because $R^\ast$ is; $k \ge 1$ with the challenge excluded rules out the trivial replay of Section 1. By Lemma 3 each $\mathsf{Probe}$ is a perfect, deterministic test for Case 2. By Lemma 4, Phases 1 and 1b output $(P^\ast[14], P^\ast[15])$ exactly. By Lemma 5 and induction on $i = 2, \dots, 15$, each subsequent byte $P^\ast[15-i]$ is output exactly given the already-recovered suffix. Hence $\hat P = P^\ast$ for every choice of the experiment's coins, so $\mathbf{Adv}^{\mathrm{PR}\text{-}\mathrm{A}} = 1$. The session count is the sum of the per-phase probe bounds, $\le (2^{16} + 43) + 14 \cdot 2^8$, with one decryption query per session. No computational assumption is used, since Lemmas 3–5 are unconditional. $\square$

#### Proof of Theorem 3 (noisy model)

After the Phase-1b reduction every decision is binary: a mask is Case 2 (signal mean $4c_0$) or, after perturbation, Case 1/3 (mean $5c_0$), a gap of $c_0$. Fix a mask and take $L$ independent samples $\tau_1, \dots, \tau_L$ with $\tau_\ell = c_0 \cdot \mathsf{cost} + \eta_\ell$, the $\eta_\ell$ independent, mean-zero and sub-Gaussian with parameter $\sigma_{\!\eta}$. The sample mean $\bar\tau$ has noise $\bar\eta = \tfrac1L\sum_\ell \eta_\ell$, which is sub-Gaussian with parameter $\sigma_{\!\eta}/\sqrt{L}$, so by the sub-Gaussian tail bound

$$\Pr\big[\,|\bar\tau - c_0\cdot\mathsf{cost}| > \tfrac{c_0}{2}\,\big] \;=\; \Pr\big[\,|\bar\eta| > \tfrac{c_0}{2}\,\big] \;\le\; 2\exp\!\Big(-\frac{L\,c_0^2}{8\,\sigma_{\!\eta}^2}\Big).$$

Thresholding $\bar\tau$ at $\tfrac92 c_0$, the midpoint of the two signal means, misclassifies the mask only on this event. Unlike a single-sample argument this holds for every $\sigma_{\!\eta} > 0$: the estimator's precision is driven by $L$, not by any assumption that one sample already separates the cases. A union bound over the at most $M = 2^{16} + 43 + 14\cdot 2^8$ masks the adversary tests (enumeration and disambiguation) gives total misclassification probability at most $2M\exp(-L c_0^2 / 8\sigma_{\!\eta}^2)$, which is $\le \epsilon$ exactly when

$$L \;\ge\; \frac{8\,\sigma_{\!\eta}^2}{c_0^2}\,\ln\frac{2M}{\epsilon}.$$

Conditioned on all tested masks being classified correctly, the run of $\mathcal{A}_{\mathrm{PR}}$ is identical to its noiseless run, so Theorem 2 gives $\hat P = P^\ast$. Hence recovery succeeds with probability at least $1 - \epsilon$. $\square$

#### Proof of Proposition 6 (necessity of the leakage)

By [[PRS11]](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20), MEE-TLS-CBC with a PRP-secure block cipher and a SUF-CMA MAC achieves Length-Hiding Authenticated Encryption in the standard model, where the decryption oracle returns only its verdict in $\{R, \bot\}$. LH-AE security implies that no efficient adversary attains non-negligible advantage in the plaintext-recovery game of Definition 12 when that game is instantiated with the verdict-only oracle. Theorem 2 attains advantage $1$ against the Model A oracle, which augments the verdict with $\mathsf{cost}(\lambda(P))$. The two differ only in that added component, so it is the component the attack depends on: removing it restores the [[PRS11]](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20) hypotheses under which recovery is infeasible. Hence the leakage is necessary, and the attack is a statement about implementations that expose it rather than about the construction. $\square$ *(The identification of [[PRS11]](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20)'s hypotheses with PRP and SUF-CMA is to be checked against [[PRS11]](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20) directly, per the ledger.)*

#### References

- [LT] N. J. AlFardan and K. G. Paterson. [Lucky Thirteen: Breaking the TLS and DTLS Record Protocols.](https://www.hit.bme.hu/~buttyan/courses/BMEVIHIM132/abib/04-TLS/Lucky13.pdf) IEEE S&P, 2013.
- [PRS11] K. G. Paterson, T. Ristenpart and T. Shrimpton. [Tag size does matter: attacks and proofs for the TLS record protocol.](https://link.springer.com/chapter/10.1007/978-3-642-25385-0_20) ASIACRYPT 2011, pp. 372–389.
- [CHVV03] B. Canvel, A. P. Hiltgen, S. Vaudenay and M. Vuagnoux. [Password Interception in a SSL/TLS Channel.](https://www.scilit.com/publications/7a4b73573841857d9102de26df89dbd3) CRYPTO 2003, LNCS 2729, pp. 583–599.
- [V02] S. Vaudenay. [Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS...](https://infoscience.epfl.ch/entities/publication/60268d2e-9c20-4d4f-9c85-6fff38c5454f/conferencedetails) EUROCRYPT 2002, pp. 534–546.
