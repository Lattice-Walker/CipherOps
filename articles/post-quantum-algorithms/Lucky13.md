The attack of Section 1.4 is from [Nadhem J. AlFardan and Kenneth G. Paterson, Information Security Group, Royal Holloway, University of London. 27th February 2013.](https://pure.tue.nl/ws/portalfiles/portal/3870148/17800025343027.pdf) ; the presentation below reorganises it around a single claim and supplies the statistical and game-based accounting explicitly.

### 1.1 The protocols

Write $x \mathbin\| y$ for concatenation, $|x|$ for byte length, $\oplus$ for bitwise XOR, and $[x]_n$ for the $n$-byte big-endian encoding of an integer $x$. For a byte string $X$ we write $X[i]$ for its $i$-th byte, indexed from zero, and $X[i \,..\, j]$ for the substring from $X[i]$ to $X[j]$ inclusive, with the convention that $X[i \,..\, i-1]$ is the empty string. The convention is needed rather than decorative: a record of length zero is admissible, and then $\mathrm{strip}$ below has upper index $-1$. Subscripts are reserved for blocks: $P_j$ is the $j$-th $b$-byte block of $P$. Thus $P_4[15]$ is the last byte of the fourth block, and no expression below uses a subscript to mean a byte.

Fix a block cipher $E : \{0,1\}^{8k} \times \{0,1\}^{8b} \to \{0,1\}^{8b}$ with block size $b$ bytes and decryption algorithm $D$, and a MAC $\mathrm{MAC} : \{0,1\}^{8k_a} \times \{0,1\}^{*} \to \{0,1\}^{8t}$ with tag size $t$ bytes. A record layer is a stateful pair $(\mathrm{Send}, \mathrm{Recv})$ over a state $\sigma = (K, \mathit{SQN}, \nu)$, where $K = (K_e, K_a)$ is the key material, $\mathit{SQN} \in \{0,\dots,2^{64}-1\}$ is a sequence number incremented once per record, and $\nu$ is the IV state, used only by the chained-IV versions.

A version of the protocol is a tuple $\Lambda_V = (\mathrm{Encode}, \Pi_V, \Phi_V, \mathrm{IV}_V, \mathcal{A}_V)$, where $\Pi_V$ is a parsing predicate applied on decryption, $\Phi_V$ is a selector naming the data on which the MAC is verified, $\mathrm{IV}_V$ is the rule producing $C_0$, and $\mathcal{A}_V$ is the set of admissible parameters $(t,b)$. We write $\Lambda_V[t,b]$ for the scheme with those parameters fixed. Since $\mathrm{Send}$ samples an IV in two of the three versions, $\Lambda_V[t,b]$ is a randomised algorithm, and equality between two such schemes below means that their outputs are identically distributed for every input and state.

#### 1.1.1 The MEE-TLS-CBC scheme

All three versions protect a record with the same MAC-Encode-Encrypt construction. The sender forms a 5-byte header $\mathit{HDR}$ consisting of a 2-byte version field, a 1-byte type field and a 2-byte length field, and for a record $R$ of length at least zero computes

$$
\begin{aligned}
\text{MAC input:} \quad & A = \mathit{SQN} \mathbin\| \mathit{HDR} \mathbin\| R, && |A| = h + |R|, \quad h = 13 \\
\text{tag:} \quad & T = \mathrm{MAC}(K_a, A) \\
\text{encoding:} \quad & P = \mathrm{Encode}(R, T, v) = R \mathbin\| T \mathbin\| [v]_1^{\,v+1} \\
\text{constraint:} \quad & |R| + t + v + 1 \equiv 0 \pmod b \\
\text{encryption:} \quad & C_j = E_{K_e}(P_j \oplus C_{j-1}), && j = 1,\dots,|P|/b
\end{aligned}
$$

where $P_1,\dots,P_{|P|/b}$ are the $b$-byte blocks of $P$ and $C_0$ is the IV. The padding string $[v]_1^{\,v+1}$ denotes $v+1$ copies of the byte whose value is $v$, for a sender-chosen $v \in \{0,\dots,255\}$, so at least one padding byte is always present and the padding may extend over several blocks; a conformant receiver must support removal of such extended padding. Exactly $h = 13$ bytes are prepended to $R$ before the MAC is computed, a quantity that Section 1.4 shows to be decisive. The data sent over the wire is $\mathit{HDR} \mathbin\| C$ with $C$ the concatenation of the ciphertext blocks; the sequence number is not transmitted, each party maintaining its own copy.

Decryption recovers the plaintext blocks as $P_j = D_{K_e}(C_j) \oplus C_{j-1}$, removes the padding, and verifies the MAC. Before that, a receiver validates the header (the version and type fields, and the length field against the ciphertext actually received) and checks that the ciphertext length is a multiple of $b$ and large enough to hold a zero-length record, a $t$-byte tag and at least one padding byte. It then reads the final plaintext byte as a padding length $\mathit{pl} = P[\,|P|-1\,]$ and removes $\mathit{pl} + 1$ bytes, which requires care: removing them blindly can underflow, leaving too few bytes for a tag and a record. What the receiver does when the padding is *not* well formed is the point on which the versions differ, and it is where the attack of Section 1.4 lives, because in that case the position of the tag is undetermined and some convention must be adopted.

Two padding predicates appear below. The length-only predicate checks that enough bytes are present,

$$\Pi_{\mathrm{len}}(P) = \bigl[\, \mathit{pl} + 1 + t \le |P| \,\bigr],$$

while the strict predicate additionally checks that every byte the padding claims is present really is:

$$
\Pi_{\mathrm{strict}}(P) =
\begin{cases}
\bigl[\, P[\,|P|-1-i\,] = \mathit{pl} \;\; \forall\, i \in \{0,\dots,\mathit{pl}\} \,\bigr], & \text{if } \Pi_{\mathrm{len}}(P) \\[2pt]
\text{false}, & \text{otherwise.}
\end{cases}
$$

The definition is given by cases rather than as a conjunction because the second line's indices need not exist: $\mathit{pl}$ ranges to $255$ while $|P|$ may be $64$, so $|P|-1-\mathit{pl}$ can be negative. When $\Pi_{\mathrm{len}}(P)$ holds we have $\mathit{pl} \le |P|-1-t$, hence $|P|-1-i \ge t \ge 0$ for every $i$ inspected, and the first line is well formed.

We also write $\mathrm{strip}(P) = \mathit{SQN} \mathbin\| \mathit{HDR} \mathbin\| P[\,0 \,..\, |P| - \mathit{pl} - 2 - t\,]$ for the MAC input obtained by removing the padding the plaintext claims, and $\mathrm{strip}_0(P) = \mathit{SQN} \mathbin\| \mathit{HDR} \mathbin\| P[\,0 \,..\, |P| - 1 - t\,]$ for the one obtained by assuming the padding has zero length. Note $|\mathrm{strip}(P)| = h + |P| - \mathit{pl} - 1 - t$ and $|\mathrm{strip}_0(P)| = h + |P| - t$.

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

#### 1.1.5 The cost of MAC verification

All three versions use HMAC. To compute the tag $T$ for a message $M$ under key $K_a$, HMAC applies the hash function $H$ twice:

$$T = H\bigl((K_a \oplus \mathit{opad}) \mathbin\| H((K_a \oplus \mathit{ipad}) \mathbin\| M)\bigr),$$

where $\mathit{opad}$ and $\mathit{ipad}$ are fixed 64-byte values and $K_a$ is zero-padded to 64 bytes. Each $H$ used here applies Merkle-Damgård strengthening, appending an 8-byte length field and at least one further byte to align the input on a 64-byte boundary, and then processes the result in 64-byte chunks with a compression function.

Throughout this section we identify the tag size $t$ with the digest size of $H$, as holds for the untruncated HMAC-MD5, HMAC-SHA-1 and HMAC-SHA-256 of Sections 1.1.3 to 1.1.5. Truncated MACs, for which the two differ, are excluded from every statement below.

<span style="color:#87A878">**Lemma 1 (verification cost).**</span> *For $t \le 55$, computing an HMAC tag over a message of $\ell$ bytes costs exactly*

$$N(\ell) = \left\lceil \frac{\ell - 55}{64} \right\rceil + 4$$

*compression function evaluations. Verification costs the same, together with a tag comparison whose cost is independent of $\ell$.*

<span style="color:#808080">*Proof.*</span>  The inner hash is applied to $(K_a \oplus \mathit{ipad}) \mathbin\| M$, of length $64 + \ell$, to which strengthening appends at least $9$ bytes and enough further bytes to reach a multiple of 64. The number of chunks is therefore $\lceil (64 + \ell + 9)/64 \rceil = \lceil (\ell + 73)/64 \rceil$, and since $73 = 128 - 55$ this equals $\lceil (\ell - 55)/64 \rceil + 2$. The outer hash is applied to $(K_a \oplus \mathit{opad})$ followed by the $t$-byte inner digest, of length $64 + t \le 119$, which with strengthening occupies exactly $2$ chunks. Each chunk costs one compression function evaluation; summing gives the formula. The comparison inspects at most $t$ bytes, a quantity fixed by the ciphersuite. $\square$

Two consequences are used throughout. First, $N$ is a step function of $\ell$ with unit steps at $\ell \equiv 56 \pmod{64}$, so two MAC inputs whose lengths straddle such a point differ in cost by at least one compression function evaluation. Second, the MAC is verified on $\Phi_V(P)$, whose length depends on how the receiver parsed the padding, so the cost of decryption depends on unauthenticated plaintext bytes. Define the verification cost of a decryption as

$$
\mathrm{cost}_V(P) =
\begin{cases}
0, & \text{if } \Phi_V(P) = \bot \\[2pt]
N\bigl(|\Phi_V(P)|\bigr), & \text{otherwise,}
\end{cases}
$$

which avoids the abuse of writing $N(\cdot) = 0$ for a function whose range is $\{4, 5, \dots\}$.


### 1.2 Observable, model, game and separation

#### 1.2.1 The observable and the cost model

The adversary does not measure processing time directly. It measures the interval between injecting a record and observing, on the wire, the alert that the receiver emits in response. We model that interval, for an injected record decrypting to plaintext $P$, as

$$\mathcal{T}(P) = c_0 + c_{\mathrm{pad}}(P) + c_H \cdot \mathrm{cost}(P) + \eta,$$

where $c_0$ collects every contribution whose magnitude is independent of $P$: block cipher decryption of a fixed number of blocks, header validation, generation and encryption of the alert, and its propagation. Here $\eta$ carries all variation of those contributions. The term $c_{\mathrm{pad}}(P)$ is the total time spent on padding processing, checking and removal together, and is left as an arbitrary function of $P$: this is deliberate, since an implementation that stops comparing at the first mismatched byte spends a time depending on the plaintext in a way no simpler parameterisation captures. Finally $c_H$ is the cost of one compression function evaluation. Where the version matters we write $c_0^V$ and $\mathrm{cost}_V$.

Write $\Delta_{\mathrm{pad}} = \sup c_{\mathrm{pad}}(P) - \inf c_{\mathrm{pad}}(P)$, both extrema over the plaintexts reachable by the records the adversary injects. Set

$$\rho = 2^{-7} + \epsilon_{\mathrm{prp}},$$

a quantity justified by Lemma 8 below, where the exponent $-7$ rather than $-8$ pays for sampling a permutation without replacement. Six hypotheses are used, and none of them is free.

- **(H1) Measurements.** A *test* consists of $L$ injections, each into a fresh session, of records chosen so that they induce the same final plaintext block. Conditioned on the history of the interaction, the $L$ measurements of a test are independent and identically distributed, and each satisfies that $\mathcal{T} - \mathbb{E}[\mathcal{T}]$ is sub-Gaussian with parameter $s$, that is $\mathbb{E}[e^{\lambda(\mathcal{T} - \mathbb{E}\mathcal{T})}] \le e^{\lambda^2 s^2/2}$ for all $\lambda \in \mathbb{R}$. Note that this is a hypothesis on the whole measurement, not on $\eta$ alone, so it also absorbs the session-to-session variation of $c_{\mathrm{pad}}$ and $\mathrm{cost}$ identified in Lemma 8. Since network jitter is autocorrelated in time, conditional independence is a constraint on the *experiment*, not a property of networks: the adversary must interleave its injections so that the measurements of one test are not consecutive. Without a tail condition of this kind no sample size suffices and every bound below fails. The hypothesis is also not free in the value of $s$: for a mask whose case varies between sessions the measurement jumps by about $c_H$ between Case 2 and Case 3, so necessarily $s = \Omega(c_H)$, and since $g < c_H$ the sample size $L = 32 s^2/g^2 \cdot \ln(2M/\varepsilon)$ is bounded below by a constant of order tens. No choice of parameters drives $L$ to $1$.
- **(H2) Padding processing does not swamp the MAC signal.** We assume
$$\Delta_{\mathrm{pad}} + 5\rho\, c_H \;<\; \frac{c_H}{3}, \qquad\text{and set}\qquad g \;=\; c_H - \Delta_{\mathrm{pad}} - 5\rho\, c_H \;>\; \frac{2c_H}{3} .$$
The first two terms of $g$ are the essential content: processing more padding costs more time while the longer padding it implies costs *less* MAC time, so the two effects oppose one another and the MAC effect must dominate for the sign of the gap to be determined. The third pays for records whose case is not the same in every session, and is small: for $\epsilon_{\mathrm{prp}} \le 2^{-8}$ it is at most $c_H/16$. The constant $1/3$ is what makes the hypothesis usable rather than merely true: it gives $\Delta_{\mathrm{pad}} < c_H/3 < g/2$, so the spread of running times *within* a class is less than half the gap *between* classes, which Lemma 3(b) needs.
- **(H3) Conformance.** The receiver's timing profile is as displayed, in particular its branch structure is exactly the selector attributed to it, header validation precedes decryption and costs the same on every branch, and the alert is generated identically on every branch. A receiver that deviates, for instance by skipping verification when too few bytes remain after depadding, is not covered by any statement below.
- **(H4) MAC security.** $\mathrm{MAC}$ is a pseudorandom function: for a uniformly chosen key, no adversary running in the time available distinguishes it from a uniformly random function with advantage exceeding $\epsilon_{\mathrm{prf}}$.
- **(H5) Block cipher security.** $E$ is a pseudorandom permutation with advantage at most $\epsilon_{\mathrm{prp}}$ against adversaries running in the time available.
- **(H6) Calibration.** The adversary knows an upper bound on $s$ and a lower bound on $g$, which is all it needs to fix $L$. It is not assumed to know $c_0$, $c_H$, $c_{\mathrm{pad}}$ or any absolute threshold; every decision below is a comparison between measured tests.

#### 1.2.2 The security game

<span style="color:#87A878">**Definition 2 (multi-session plaintext recovery).**</span> Fix a scheme $\Lambda[t,b]$ and a target block $P^{*} \in \{0,1\}^{8b}$. The experiment $\mathbf{Exp}(\mathcal{A}, P^{*}, n)$ runs $n$ sessions. In session $i$ a fresh key $K^{(i)}$ is drawn uniformly and independently, and the application transmits a record stream in which $P^{*}$ occupies a fixed position known to $\mathcal{A}$. The adversary observes the traffic of session $i$ and may inject one record into it, learning the resulting alert symbol and the value of $\mathcal{T}$ for that injection; the injection terminates the session, errors being fatal. After the $n$ sessions $\mathcal{A}$ outputs $\hat{P}$, and succeeds if $\hat{P} = P^{*}$. The probability is over the keys, the sender's IVs, the noise, and $\mathcal{A}$'s coins. Write $n_s$ for the maximum number of records the sender transmits in any one session.

$\mathcal{A}$ is a $(q, L, \delta)$-attack on $\Lambda[t,b]$ if it uses at most $q$ sessions, organises them into tests of at most $L$ sessions each in the sense of (H1), and satisfies $\Pr[\mathbf{Exp}(\mathcal{A}, P^{*}, q) \text{ succeeds}] \ge \delta$ *for every* $P^{*}$. A scheme admitting such an attack with $\delta \ge 1/2$ and $q$ feasible is called broken. Two points deserve emphasis. No distribution on $P^{*}$ is assumed anywhere, and none of the results below needs one. And $L$ counts sessions per *test*, not repetitions of a fixed ciphertext: the records injected within one test are different strings, since each session has its own key and its own $C', C^{*}$, and what they share is the induced final plaintext block.

#### 1.2.3 The separation lemma

<span style="color:#87A878">**Lemma 3 (sequential separation and decision rules).**</span> *Assume (H1). Let $\mathfrak{F}$ be a family of tests and suppose constants $\mu, \gamma$ exist such that every member of $\mathfrak{F}$ is either* fast*, with $\mathbb{E}[\mathcal{T}] \le \mu$, or* slow*, with $\mathbb{E}[\mathcal{T}] \ge \mu + \gamma$. Let $\mathcal{A}$ perform at most $M$ tests drawn from $\mathfrak{F}$, the $j$-th chosen as an arbitrary function of the history $\mathcal{F}_{j-1}$ of all previous measurements, and let $\bar{T}_j$ be its sample mean over $L$ measurements. If*

$$L \;\ge\; \frac{32 s^2}{\gamma^2} \ln \frac{2M}{\varepsilon},$$

*then the event $\mathcal{E}$ that $|\bar{T}_j - \mathbb{E}[\mathcal{T}_j]| < \gamma/8$ holds simultaneously for all $j$ has probability at least $1 - \varepsilon$, and on $\mathcal{E}$:*

*(a)* **Ranking.** *Every fast test's sample mean is strictly smaller than every slow test's. Hence in a batch known to contain at least one fast test, the test of smallest sample mean is fast; symmetrically, in a batch known to contain at least one slow test, the test of largest sample mean is slow.*

*(b)* **Comparison against a reference.** *Suppose the fast members of $\mathfrak{F}$ have expectations spanning at most $\gamma/2$, and let $R$ be a test already known to be fast. Then an arbitrary test $Z$ is fast if and only if $\bar{T}_Z - \bar{T}_R < 3\gamma/4$. Symmetrically, if the slow tests' expectations span at most $\gamma/2$ and $R$ is known to be slow, then $Z$ is slow if and only if $\bar{T}_R - \bar{T}_Z < 3\gamma/4$.*

<span style="color:#808080">*Proof.*</span>  Fix $j$ and condition on $\mathcal{F}_{j-1}$, which determines the $j$-th test. By (H1) its $L$ measurements are conditionally i.i.d. with $\mathcal{T} - \mathbb{E}[\mathcal{T}]$ sub-Gaussian with parameter $s$, so the centred sample mean is conditionally sub-Gaussian with parameter $s/\sqrt{L}$ and the standard sub-Gaussian tail bound gives $\Pr[\,|\bar{T}_j - \mathbb{E}[\mathcal{T}_j]| \ge \gamma/8 \mid \mathcal{F}_{j-1}\,] \le 2\exp(-L\gamma^2/(32 s^2)) =: \beta$. Writing $B_j$ for that event, $\Pr[B_j] = \mathbb{E}[\Pr[B_j \mid \mathcal{F}_{j-1}]] \le \beta$, and a union bound gives $\Pr[\bigcup_j B_j] \le M\beta \le \varepsilon$ for $L$ as stated. The bound holds however the $j$-th test was selected from $\mathfrak{F}$, which is what adaptivity requires. Note that the dichotomy is required only of $\mathfrak{F}$, not of every record an unrestricted adversary could inject: records of other lengths have other cost profiles, and the lemma says nothing about them.

For (a), on $\mathcal{E}$ a fast test has $\bar{T} < \mu + \gamma/8$ and a slow one has $\bar{T} > \mu + \gamma - \gamma/8 = \mu + 7\gamma/8$. For (b), if $Z$ is fast then $|\mathbb{E}[\mathcal{T}_Z] - \mathbb{E}[\mathcal{T}_R]| \le \gamma/2$ by the spread hypothesis, so $\bar{T}_Z - \bar{T}_R < \gamma/2 + 2 \cdot \gamma/8 = 3\gamma/4$; if $Z$ is slow then $\mathbb{E}[\mathcal{T}_Z] - \mathbb{E}[\mathcal{T}_R] \ge \gamma$, so $\bar{T}_Z - \bar{T}_R > \gamma - 2 \cdot \gamma/8 = 3\gamma/4$. The two cases are exclusive and exhaustive, which gives the stated equivalence; the symmetric statement is identical with signs reversed. $\square$

Part (a) needs no knowledge of any constant. Part (b) needs only $\gamma$, which (H6) supplies. At no point does the adversary evaluate the threshold $\mu + \gamma/2$, whose position depends on constants it does not know: every decision below is a comparison between measured tests.


### 1.3 Transfer from TLS 1.2 to TLS 1.1

<span style="color:#87A878">**Lemma 4 (record-layer identity).**</span> *For every $t \in \{16, 20\}$ and every $b \in \{8,16\}$, the schemes $\Lambda_{1.2}[t,b]$ and $\Lambda_{1.1}[t,b]$ are identical: for every state and input their outputs are identically distributed, and their cost functions agree pointwise.*

<span style="color:#808080">*Proof.*</span>  Both use the $\mathrm{Encode}$ of Section 1.1.2, both sample $C_0$ uniformly and independently per record, both apply $\Pi_{\mathrm{strict}}$, and $\Phi_{1.2} = \Phi_{1.1}$ by definition, so $\mathrm{cost}_{1.2} = \mathrm{cost}_{1.1}$ pointwise. The parameter restriction is what makes the statement true: $\{16,20\}$ is exactly the set of tag sizes admitted by both, TLS 1.1 having no HMAC-SHA-256. $\square$

<span style="color:#87A878">**Definition 5 (IV-obliviousness).**</span> An adversary is *IV-oblivious* if, for every value of $C_0$ that the receiver's state supplies, it can construct records inducing its intended plaintext blocks other than the first, with unchanged success probability. Such an adversary may be run against a chained-IV receiver, where $C_0$ is inherited from the preceding record and is not transmitted, at the cost of one fewer transmitted block; the records it puts on the wire are then different strings, but they induce the same plaintext blocks from the second onwards.

<span style="color:#87A878">**Theorem 6 (TLS 1.2 $\Rightarrow$ TLS 1.1).**</span> *Assume (H1)–(H6) and let $\mathcal{A}$ be a $(q, L, \delta)$-attack on $\Lambda_{1.2}[t,b]$ for some $t \in \{16,20\}$, $b \in \{8,16\}$, whose output depends on the observed legitimate traffic only through the positions of ciphertext blocks, and otherwise only on the alert symbols and timings it collects. Then $\mathcal{A}$, run without modification, is a $(q, L, \delta)$-attack on $\Lambda_{1.1}[t,b]$.*

<span style="color:#808080">*Proof.*</span>  By Lemma 4 the two receivers agree as randomised functions of $(K, \mathit{SQN}, C)$ and their cost functions agree pointwise. Both carry out the same fixed processing outside the parse and emit the same alert, so $c_0^{1.1} = c_0^{1.2}$, and they share $c_{\mathrm{pad}}$ and $c_H$; by (H1) the law of the centred measurement is common. Hence for every injected record the alert symbol and the law of $\mathcal{T}$ coincide across the two experiments. The experiments are not identical in every respect: the two versions carry different bytes in the version field of $\mathit{HDR}$, which the adversary can see in the legitimate traffic. But by hypothesis $\mathcal{A}$ reads that traffic only for block positions, which are the same, so its output is a function of observables whose joint law coincides, and is therefore identically distributed in the two experiments. The adversary of Theorem 7 satisfies the hypothesis, since it uses the traffic only to locate $C'$ and $C^{*}$. The transformation is the identity map, so $q$, $L$ and $\delta$ are preserved exactly. $\square$

<span style="color:#87A878">**Remark 1 (scope).**</span> Theorem 6 transfers an attack on $\Lambda_{1.2}[t,b]$ to $\Lambda_{1.1}[t,b]$ with the *same* $(t,b)$. Section 1.4 supplies an attack for $(20,16)$ only, so what follows concerns that pair. The configurations $(16,16)$, $(20,8)$ and $(16,8)$ require the case analysis of Lemma 9 to be redone with different arithmetic and are not claimed here; for $t = 16$ in particular the analogue of Case 2 requires six or more padding bytes and the resulting search is far more expensive. It would be an overstatement to conclude from this document that *every* CBC configuration of TLS 1.1 is broken. The hypothesis $t \in \{16,20\}$ is also necessary: an attack requiring $t = 32$ could not transfer, since $\Lambda_{1.1}[32,b]$ is not a scheme TLS 1.1 defines.


### 1.4 The special case of TLS 1.2 is broken

<span style="color:#87A878">**Theorem 7.**</span> *Assume (H1)–(H6). Let $\varepsilon \in (0,1)$ and set*

$$L = \left\lceil \frac{32 s^2}{g^2} \ln \frac{2^{18}}{\varepsilon} \right\rceil.$$

*Then there is an IV-oblivious $(q, L, \delta)$-attack on $\Lambda_{1.2}[20,16]$ with*

$$q \le L \cdot \bigl(2^{16} + 14 \cdot 2^8 + 2\bigr), \qquad \delta \ge 1 - \varepsilon - q\bigl(2^{-158} + \epsilon_{\mathrm{prf}} + \epsilon_{\mathrm{prp}}\bigr).$$

#### 1.4.1 Setup

In each session let $C^{*}$ be the ciphertext block carrying the target plaintext $P^{*}$ and let $C'$ be the block preceding it, which may be that session's IV or the last block of the preceding record. Then

$$P^{*} = D_{K_e}(C^{*}) \oplus C'.$$

The adversary is a man-in-the-middle: it observes the protected traffic and injects records of its own composition. It need not prevent messages from reaching their destination and needs no chosen-plaintext capability. The blocks $C'$ and $C^{*}$ are session-specific and the adversary locates them by position; nothing below depends on their taking different values in different sessions. What is constant across sessions is the plaintext $P^{*}$, which is what Definition 2 fixes.

#### 1.4.2 The injected record and its cases

Let $\Delta$ be a block of 16 bytes and consider the decryption of

$$C^{\mathrm{att}}(\Delta) = \mathit{HDR} \mathbin\| C_0 \mathbin\| C_1 \mathbin\| C_2 \mathbin\| (C' \oplus \Delta) \mathbin\| C^{*},$$

where $\mathit{HDR}$ carries the version and type fields copied from observed traffic and a length field matching the four non-IV blocks, so that header validation passes. The penultimate block is a masked copy of $C'$ and the last is $C^{*}$; the blocks $C_0, C_1, C_2$ are arbitrary and no step below constrains $C_0$, so the adversary is IV-oblivious in the sense of Definition 5. The 64-byte plaintext is $P = P_1 \mathbin\| P_2 \mathbin\| P_3 \mathbin\| P_4$ with

$$P_4 = D_{K_e}(C^{*}) \oplus (C' \oplus \Delta) = P^{*} \oplus \Delta,$$

so the adversary controls the final plaintext block up to the unknown constant $P^{*}$. Since $|P| = 64 \ge 0 + 20 + 1$, the length sanity check passes. A *test at mask $\Delta$* means the test of (H1) whose $L$ injections use $C^{\mathrm{att}}(\Delta)$ built from each session's own $C', C^{*}$; every injection of that test induces the same $P_4 = P^{*} \oplus \Delta$, which is what (H1) requires.

<span style="color:#87A878">**Lemma 8 (what is and is not session-invariant).**</span> *Fix a mask $\Delta$. Across the sessions of the test at $\Delta$ the block $P_4$, hence $\mathit{pl} = P_4[15]$, is invariant, while $P_1, P_2, P_3$ vary. If $\mathit{pl} \le 15$ or $\mathit{pl} \ge 44$ then $\Pi_{\mathrm{strict}}(P)$ takes the same value in every session; we call the mask* stable*. Otherwise $\Pr[\Pi_{\mathrm{strict}}(P)] \le \rho = 2^{-7} + \epsilon_{\mathrm{prp}}$ in each session.*

<span style="color:#808080">*Proof.*</span>  $P_4 = P^{*} \oplus \Delta$ by the display above, and $P^{*}$ is fixed by Definition 2, so $P_4$ is invariant. In contrast $P_3 = D_{K_e}(C' \oplus \Delta) \oplus C_2$ depends on the session key and on $C'$, and likewise $P_1, P_2$. Now $\Pi_{\mathrm{strict}}$ inspects $P[\,63 - \mathit{pl} \,..\, 63\,]$ when $\Pi_{\mathrm{len}}$ holds, that is when $\mathit{pl} \le 43$. If $\mathit{pl} \le 15$ those indices are all at least 48, so they lie in $P_4$ and the predicate is a function of invariant data. If $\mathit{pl} \ge 44$ then $\Pi_{\mathrm{len}}$ fails and the predicate is false in every session. Otherwise $16 \le \mathit{pl} \le 43$ and the predicate requires, among others, that $P[47]$ equal $\mathit{pl}$; this byte is inspected for every $\mathit{pl} \ge 16$, and it is the last byte of $P_3$, so it suffices to bound its distribution. (For $\mathit{pl} \ge 32$ the inspected range also reaches into $P_2$, which only lowers the probability further.) Replacing $E$ by a uniformly random permutation changes the probability by at most $\epsilon_{\mathrm{prp}}$ by (H5), and under a random permutation $D(C' \oplus \Delta)$ is uniform on the values not fixed by the at most $n_s + 1$ other queries of that session, so $P[47]$ takes the prescribed value with probability at most $2^{-8}(1 - (n_s+1)2^{-128})^{-1} \le 2^{-7}$. Hence $\Pr[\Pi_{\mathrm{strict}}(P)] \le 2^{-7} + \epsilon_{\mathrm{prp}} = \rho$. $\square$

<span style="color:#87A878">*Lemma 9 (three cases).**</span> *On decryption of $C^{\mathrm{att}}(\Delta)$ by $\Lambda_{1.2}[20,16]$, exactly one of the following holds, and $\mathrm{cost}_{1.2}(P)$ equals 5 in the first and third cases and 4 in the second.*

<span style="color:#808080">*Proof.*</span>  The receiver reads $\mathit{pl} = P_4[15]$, and the cases are determined by that byte together with $\Pi_{\mathrm{strict}}$, hence are mutually exclusive and exhaustive.

1. **$\mathit{pl} = 0$.** Then $\Pi_{\mathrm{strict}}$ holds, since $0 + 1 + 20 \le 64$ and the one byte examined is $\texttt{0x00}$ by assumption. One padding byte is removed and 20 read as the tag, so $|\mathrm{strip}(P)| = 13 + 64 - 0 - 1 - 20 = 56$.

2. **$\mathit{pl} \ge 1$ and $\Pi_{\mathrm{strict}}(P)$ holds.** Then $|\mathrm{strip}(P)| = 56 - \mathit{pl} \le 55$.

3. **$\Pi_{\mathrm{strict}}(P)$ fails.** The second branch of $\Phi_{1.2}$ applies and $|\mathrm{strip}_0(P)| = 13 + 64 - 20 = 57$.

By Lemma 1, $N(56) = N(57) = 5$ while $N(\ell) = 4$ for all $\ell \le 55$, and $\mathrm{cost}_{1.2} = N(|\Phi_{1.2}(P)|)$ since $\Phi_{1.2}$ never returns $\bot$. $\square$

Call a mask *good* if it is stable in the sense of Lemma 8 and its decryptions fall in Case 2, so that $1 \le \mathit{pl} \le 15$ and $\Pi_{\mathrm{strict}}$ holds in every session.

<span style="color:#87A878">**Lemma 10 (the hypothesis of Lemma 3 holds).**</span> *Set $\mu = c_0^{1.2} + \sup c_{\mathrm{pad}} + 4c_H$, the supremum over plaintexts reachable by records $C^{\mathrm{att}}(\Delta)$. Then the test at a good mask has $\mathbb{E}[\mathcal{T}] \le \mu$, and the test at every other mask has $\mathbb{E}[\mathcal{T}] \ge \mu + g$.*

<span style="color:#808080">*Proof.*</span>  At a good mask every session gives Case 2, so $\mathbb{E}[\mathcal{T}] = c_0^{1.2} + \mathbb{E}[c_{\mathrm{pad}}(P)] + 4c_H \le \mu$, the noise having mean zero by (H1). At any other mask, write $\pi$ for the probability that a session falls in Case 2. If the mask is stable then $\pi = 0$; otherwise $\pi \le \rho$ by Lemma 8. Since $\mathrm{cost}_{1.2} \in \{4,5\}$ with the value 4 exactly on Case 2, $\mathbb{E}[\mathrm{cost}_{1.2}] = 5 - \pi \ge 5 - \rho$, whence $\mathbb{E}[\mathcal{T}] \ge c_0^{1.2} + \inf c_{\mathrm{pad}} + (5-\rho)c_H = \mu - \Delta_{\mathrm{pad}} + c_H - \rho c_H \ge \mu + g$ by (H2). $\square$

Moreover the expectations of good tests all lie in $[\mu - \Delta_{\mathrm{pad}}, \mu]$, an interval of width $\Delta_{\mathrm{pad}} < c_H/3 < g/2$ by (H2), so the spread hypothesis of Lemma 3(b) is met with the good tests as the fast class. This is where (H2) earns its keep three times over: good masks are not equicostly, since Case 2 spans $\mathit{pl} \in \{1,\dots,15\}$; unstable masks are fast in a $\rho$-fraction of sessions; and the within-class spread must stay below half the gap for a single test to be classifiable against a reference.

Note where the one-evaluation gap comes from: $h = 13$ and $t = 20$ place the Case 1 input at 56 bytes, one byte past the threshold of Lemma 1. Had $h$ been 12, Case 1 would also be fast and the search below would cost $2^8$ rather than $2^{16}$. Had $t$ been 16, Case 2 would require $\mathit{pl} \ge 5$, hence six or more padding bytes, and the search would be far more expensive. Had $t$ been 32, a 64-byte record would give $|\mathrm{strip}(P)| \le 44$ and $|\mathrm{strip}_0(P)| = 45$ in every case, so *no* gap would exist at this record length and the adversary would have to lengthen the injected record to five blocks before any separation appeared. This is what makes $\Lambda_{1.2}[20,16]$ the special case.

<span style="color:#87A878">**Lemma 11 (at most two good masks).**</span> *Fix $\Delta[0\,..\,13]$ and let $(\Delta[14], \Delta[15])$ range over its $2^{16}$ values, so that $P_4[0\,..\,13]$ is fixed while $P_4[14], P_4[15]$ vary. Exactly one mask is good with $\mathit{pl} = 1$, namely that with $P_4[14] = P_4[15] = \texttt{0x01}$; note that $2^8$ masks have $\mathit{pl} = 1$, since $\mathit{pl}$ depends on $\Delta[15]$ alone, and what is unique is the mask meeting the predicate. At most one further mask is good, and only if $f = P_4[13]$ satisfies $2 \le f \le 15$ and $P_4[15-f \,..\, 13]$ all equal $f$. Modifying $\Delta[13]$ leaves the first good and makes the second not good.*

<span style="color:#808080">*Proof.*</span>  Goodness requires $1 \le \mathit{pl} = P_4[15] \le 15$ and $P_4[15-i] = \mathit{pl}$ for $i = 0,\dots,\mathit{pl}$; since $\mathit{pl} \le 15$ every index involved is at least $0$, so all bytes inspected lie in $P_4$ and are fixed except $P_4[14], P_4[15]$. If $\mathit{pl} = 1$ only those two are inspected and both must be $\texttt{0x01}$, fixing the mask uniquely, and $\Pi_{\mathrm{len}}$ holds as $1 + 21 \le 64$. If $\mathit{pl} \ge 2$ then $P_4[13]$ is inspected and must equal $\mathit{pl}$, so $\mathit{pl} = f$ is forced, and $P_4[14] = P_4[15] = f$ then fixes the mask uniquely; the further inspected bytes $P_4[15-f\,..\,13]$ are fixed, giving the stated condition. Hence at most two good masks. For the last claim, modifying $\Delta[13]$ changes $P_4[13]$ and nothing else inspected: a mask with $\mathit{pl} = 1$ never has $P_4[13]$ inspected and remains good, while one with $\mathit{pl} = f \ge 2$ acquires $P_4[13] \ne f$, so $\Pi_{\mathrm{strict}}$ fails in every session and it is not good. $\square$

<span style="color:#87A878">**Lemma 12 (uniqueness in the byte-by-byte phase).**</span> *Let $1 \le k \le 15$ and suppose $\Delta[16-k\,..\,15]$ is fixed so that $P_4[16-k\,..\,15]$ consists of $k$ copies of the byte $k$. Let $\Delta[15-k]$ range over its $2^8$ values. Then exactly one resulting mask satisfies $\Pi_{\mathrm{strict}}(P) \wedge (\mathit{pl} \ge 1)$ in every session, namely that with $P_4[15-k] = k$, and that mask is good; the others are not good.*

<span style="color:#808080">*Proof.*</span>  The receiver reads $\mathit{pl} = P_4[15] = k$, fixed by hypothesis, with $1 \le k \le 15 \le 43$, so $\Pi_{\mathrm{len}}$ holds and all inspected indices lie in $P_4$, making every mask in this enumeration stable. The predicate then requires exactly $P_4[15-i] = k$ for $i = 0,\dots,k$. The bytes with $i < k$ are fixed and already equal $k$; the byte with $i = k$ is $P_4[15-k]$, which the enumeration sets to each value exactly once. $\square$

#### 1.4.3 Proof of Theorem 7

The adversary performs at most $M = 2^{16} + 14 \cdot 2^8 + 2 < 2^{17}$ tests of $L$ sessions each, so $q \le LM$, the stated bound. By Lemma 10 the hypothesis of Lemma 3 holds with fast $=$ good, for the constants $\mu$ and $g$ there; since $2M < 2^{18}$, the stated $L$ meets that lemma's requirement at parameter $\varepsilon$. Let $\mathcal{E}$ be its event, of probability at least $1 - \varepsilon$. The tests below are chosen adaptively, which Lemma 3 permits, and on $\mathcal{E}$ every good test's sample mean is strictly smaller than every non-good test's. Only that ordering is used.

*Phase 1.* Fix $\Delta[0\,..\,13]$ arbitrarily and run the $2^{16}$ tests indexed by $(\Delta[14], \Delta[15])$. By Lemma 11 the mask $M_1$ with $P_4[14] = P_4[15] = \texttt{0x01}$ is good, so the batch contains a good test and, by Lemma 3(a), the test $G$ of smallest sample mean is good. By Lemma 10 the good tests form the fast class and their spread is below $g/2$, so Lemma 3(b) applies with reference $G$: for any test $Z$, the adversary decides goodness by the rule $\bar{T}_Z - \bar{T}_G < 3g/4$. Applying it to the remaining $2^{16}-1$ Phase-1 tests determines the good set exactly, which by Lemma 11 is either $\{G\}$ or $\{G, X\}$ for one further mask $X$.

If the good set is $\{G\}$ then $G = M_1$, since $M_1$ is good and is the only good mask. Otherwise the good set is $\{M_1, M_f\}$ in some order; run one further test on $G'$, the mask obtained from $G$ by modifying $\Delta[13]$, and classify it by the same reference rule. By Lemma 11, $G' $ is good exactly when $G = M_1$; so $G = M_1$ if $G'$ is good and $X = M_1$ otherwise. Either way $M_1$ is identified, and since it has $P_4[14] = P_4[15] = \texttt{0x01}$,

$$P^{*}[14] = \Delta[14] \oplus \texttt{0x01}, \qquad P^{*}[15] = \Delta[15] \oplus \texttt{0x01}.$$

Note that no step required deciding the goodness of a test in isolation: every decision was a ranking within the Phase-1 batch or a comparison against the known-good $G$.

*Phase 2.* For $k = 2, 3, \dots, 15$ in turn, use the bytes already recovered to fix $\Delta[16-k\,..\,15]$ so that $P_4[16-k\,..\,15]$ is $k$ copies of the byte $k$, and run the $2^8$ tests indexed by $\Delta[15-k]$. By Lemma 12 exactly one is good, so the batch contains a good test and by Lemma 3(a) it is the one of smallest sample mean, and it has $P_4[15-k] = k$, whence $P^{*}[15-k] = \Delta[15-k] \oplus k$. Fourteen iterations recover $P^{*}[0\,..\,13]$ at a cost of $14 \cdot 2^8$ tests.

*Accounting.* Two events spoil the run. The first is the failure of $\mathcal{E}$, of probability at most $\varepsilon$. The second is that some injected record verifies, in which case the receiver accepts it and the behaviour is not that of Lemma 9.

To bound the second, replace the session's MAC by a uniformly random function $f$, at a cost of $\epsilon_{\mathrm{prf}}$ by (H4), and $E$ by a uniformly random permutation, at a cost of $\epsilon_{\mathrm{prp}}$ by (H5). Write $A = \Phi_{1.2}(P)$ for the injected record's MAC input and $T_{\mathrm{inj}}$ for the $t$ tag bytes carried in $P$; verification succeeds exactly when $f(A) = T_{\mathrm{inj}}$. The blocks $P_1, P_2, P_3$ are images of the permutation inputs $C_1, C_2, C' \oplus \Delta$, hence uniform on the values left by the at most $n_s + 1$ other evaluations of that session, while $P_4 = P^{*} \oplus \Delta$ is pinned by the environment and is the *same in every session of the test*.

Which bytes $A$ and $T_{\mathrm{inj}}$ occupy depends first on which branch of $\Phi_{1.2}$ the record takes, and only then on $\mathit{pl}$; splitting on $\mathit{pl}$ alone would be an error, since the two branches place the tag in different positions. We therefore distinguish three cases, which are exhaustive.

(i) *The failing branch*, that is Case 3 of Lemma 9. Here $A = \mathrm{strip}_0(P) = \mathit{SQN} \mathbin\| \mathit{HDR} \mathbin\| P[\,0 \,..\, 43\,]$ carries $44$ plaintext bytes, all lying in $P_1 P_2 P_3$ and so uniform, so $A$ agrees with a given sender query only if all $44$ agree and $A$ is fresh except with probability at most $n_s 2^{-352}$. When $A$ is fresh, $f(A)$ is uniform on $2^{8t}$ values and independent of $T_{\mathrm{inj}}$, which is a function of the permutation alone, so the match has probability $2^{-8t}$. Note that here $T_{\mathrm{inj}} = P[\,44 \,..\, 63\,]$ has sixteen of its twenty bytes inside $P_4$ and is therefore *not* uniform; this case must argue from $f(A)$, not from the tag.

(ii) *The accepting branch with $\mathit{pl} \ge 15$.* The tag occupies $P[\,43-\mathit{pl} \,..\, 62-\mathit{pl}\,]$ with $62 - \mathit{pl} \le 47$, so $T_{\mathrm{inj}}$ lies wholly in $P_1 P_2 P_3$ and is uniform on at least $2^{8t}\bigl(1 - (n_s+1)2^{-8b}\bigr)$ values. Since $f$ does not act on those bytes, $T_{\mathrm{inj}}$ is independent of $f(A)$ whether or not $A$ is fresh, and the match has probability at most $2^{-8t}\bigl(1 - (n_s+1)2^{-8b}\bigr)^{-1} \le 2^{-159}$.

(iii) *The accepting branch with $\mathit{pl} \le 14$.* Here $A$ contains the plaintext bytes $P[\,0 \,..\, 42-\mathit{pl}\,]$, of which there are $43 - \mathit{pl} \ge 29$, all lying in $P_1 P_2 P_3$ and so uniform, so $A$ is fresh except with probability at most $n_s 2^{-231}$; and when $A$ is fresh $f(A)$ is uniform on $2^{8t}$ values and independent of $T_{\mathrm{inj}}$, giving a match probability of $2^{-8t}$.

Taking the worst case, verification succeeds with probability at most $2^{-159} + n_s 2^{-231} \le 2^{-158}$ for any $n_s \le 2^{72}$. Observe which object carries each case: in (i) and (iii) it is $f(A)$, uniform once freshness is established, and in (ii) it is the tag, uniform outright. Neither mechanism may be borrowed by the other case, and (ii) genuinely needs its own: freshness fails there, since at $\mathit{pl} = 43$ the input $A$ reduces to $\mathit{SQN} \mathbin\| \mathit{HDR}$ and carries no plaintext byte at all, so it coincides with the MAC input of any legitimate zero-length record at the same sequence number and header.

Summing over the $q$ injections, each in a session with an independent key, bounds the second event by $q(2^{-158} + \epsilon_{\mathrm{prf}} + \epsilon_{\mathrm{prp}})$. Off the two events the adversary outputs $P^{*}$, for every $P^{*}$, which gives the stated $\delta$. $\square$

<span style="color:#87A878">**Remark 2 (instantiating $q$).**</span> Definition 2 makes feasibility of $q$ part of what *broken* means, so the bound of Theorem 7 must be turned into a number. Writing $r = s/g$ for the ratio of the noise parameter to the gap, the theorem gives

$$q \;=\; L \cdot M \;=\; \bigl\lceil 32 r^2 \ln(2^{18}/\varepsilon) \bigr\rceil \cdot 69122, \qquad 69122 = 2^{16} + 14 \cdot 2^8 + 2 .$$

One floor on $r$ can be proved, and it comes from the protocol rather than from the network. Sub-Gaussianity gives $s \ge \sigma$, and for an unstable mask the measurement is a two-point mixture with weight $\rho$ and separation $c_H$, so $\sigma \ge \sqrt{\rho(1-\rho)}\, c_H > 0.107\, c_H$; since Phase 1 enumerates all $256$ values of $\mathit{pl}$ such a mask is always tested, and with $g < c_H$ this yields $r > 0.107$ unconditionally. No upper bound on $r$ is proved here, and in practice $r$ is governed by jitter rather than by the flicker, since $c_H$ is sub-microsecond while wide-area jitter is not; the figures below are therefore parameterised by $r$ rather than settled. Taking $\varepsilon = 2^{-10}$, so $\ln(2^{18}/\varepsilon) < 19.5$, gives $L = \lceil 622\, r^2 \rceil$ and hence

$$q \approx 2^{16.1} \cdot \lceil 622\, r^2 \rceil,$$

that is $q \approx 2^{25.4}$ sessions at $r = 1$, $q \approx 2^{32}$ at $r = 10$, and $q \approx 2^{38.6}$ at $r = 100$. The attack is therefore feasible exactly when $r$ is small, which is to say when the adversary sits close enough to the receiver that jitter is comparable to a single compression function evaluation. This is a real restriction and it is the quantitative content of the word *feasible* in Definition 2; it is not established here for a remote adversary.

<span style="color:#87A878">**Corollary 13.**</span> *Assume (H1)–(H6). The scheme $\Lambda_{1.1}[20,16]$ is broken: the attack of Theorem 7 uses $t = 20$, so Theorem 6 applies and carries it over with the same $(q, L, \delta)$.* $\square$

### 1.5 TLS 1.0

TLS 1.0 fixes neither the padding predicate nor the behaviour on failure, so Section 1.1.3 distinguished four receiver families in a $2 \times 2$ grid. We treat them separately; there is no single dichotomy. The two families using $\Pi_{\mathrm{strict}}$ are broken below, by different arguments; the two using $\Pi_{\mathrm{len}}$ are not covered, for the reason given in Remark 3.

<span style="color:#87A878">**Theorem 14 ($\mathsf{R}_{\mathrm{mac}}$ receivers).**</span> *Assume (H1)–(H6). A TLS 1.0 receiver of family $\mathsf{R}_{\mathrm{mac}}$ with $t = 20$, $b = 16$ is broken by the attack of Theorem 7, with the same $(q, L, \delta)$.*

<span style="color:#808080">*Proof.*</span>  Such a receiver implements $\Pi_{\mathrm{strict}}$ and $\Phi_{1.1} = \Phi_{1.2}$, so its cost function is that of $\Lambda_{1.2}[20,16]$ and Lemmas 8–12 apply verbatim. The only remaining difference is that $C_0$ is chained rather than sampled and is not transmitted. The adversary of Theorem 7 is IV-oblivious, so by Definition 5 it injects a four-block record inducing the same $P_2, P_3, P_4$; no step of the proof inspects $P_1$, and $|P| = 64$ as before. $\square$

<span style="color:#87A878">**Lemma 15 (a padding oracle for $\mathsf{R}_{\mathrm{strict}}$).**</span> *Assume (H1)–(H6). Fix $M \ge 1$ and $\varepsilon \in (0,1)$, and consider a receiver of family $\mathsf{R}_{\mathrm{strict}}$ with $t = 20$, $b = 16$ tested with records $C^{\mathrm{att}}(\Delta)$. Call a mask* sound *if $\Pi_{\mathrm{strict}}(P)$ holds in every session, and set $\gamma_0 = 4g$. With*

$$L' = \left\lceil \frac{32 s^2}{\gamma_0^{2}} \ln \frac{2M}{\varepsilon} \right\rceil$$

*sessions per test, the conclusions of Lemma 3 hold over $M$ adaptively chosen tests with probability at least $1 - \varepsilon$, taking the non-sound masks as the fast class and the sound ones as the slow class; moreover both classes have spread below $\gamma_0/2$, so part (b) is available with a reference of either kind. Note that $\gamma_0$ is computable from the lower bound on $g$ that (H6) supplies, so the adversary can evaluate the decision rules; the true gap $3c_H + g$ is larger but involves $c_H$, which it does not know.*

<span style="color:#808080">*Proof.*</span>  If $\Pi_{\mathrm{strict}}(P)$ fails then $\Phi(P) = \bot$ and $\mathrm{cost}(P) = 0$; if it holds then $\mathrm{cost}(P) = N(56 - \mathit{pl}) \in \{4,5\}$ by Lemmas 1 and 9. Set $\mu' = c_0 + \sup c_{\mathrm{pad}} + 5\rho\, c_H$. A non-sound mask holds with probability $\pi \le \rho$ by Lemma 8, being stable-failing or unstable, so $\mathbb{E}[\mathcal{T}] \le c_0 + \sup c_{\mathrm{pad}} + 5 \pi c_H \le \mu'$, and its expectation is at least $c_0 + \inf c_{\mathrm{pad}}$, so the non-sound class spans at most $\Delta_{\mathrm{pad}} + 5\rho c_H < c_H/3$. A sound mask has $\mathbb{E}[\mathcal{T}] \ge c_0 + \inf c_{\mathrm{pad}} + 4 c_H = \mu' - \Delta_{\mathrm{pad}} - 5\rho c_H + 4c_H = \mu' + 3c_H + g$, and at most $c_0 + \sup c_{\mathrm{pad}} + 5c_H$, so the sound class spans at most $\Delta_{\mathrm{pad}} + c_H < 4c_H/3$.

It remains to check that $\gamma_0 = 4g$ is a legitimate working gap. Since $\Delta_{\mathrm{pad}} > 0$ and $\rho > 0$ we have $g < c_H$, so $3c_H + g > 4g = \gamma_0$ and the separation hypothesis of Lemma 3 holds a fortiori with $\gamma_0$. For the spreads, (H2) gives $g > 2c_H/3$, hence $\gamma_0/2 = 2g > 4c_H/3$, which exceeds both $c_H/3$ and $\Delta_{\mathrm{pad}} + c_H < 4c_H/3$. Lemma 3 with $\mu'$ and $\gamma_0$ therefore gives the claim. $\square$

<span style="color:#87A878">**Lemma 16 (recovery from the oracle).**</span> *Under the hypotheses of Lemma 15 with $M = 16 \cdot 2^8 + 2$, the adversary recovers $P^{*}$ using at most $M$ tests.*

<span style="color:#808080">*Proof.*</span>  Soundness is the predicate $\Pi_{\mathrm{strict}}$, which unlike Case 2 of Section 1.4 also admits $\mathit{pl} = 0$. Fix $\Delta[0\,..\,14]$ and run the $2^8$ tests indexed by $\Delta[15]$, so only $P_4[15]$ varies. The mask $M_0$ with $P_4[15] = \texttt{0x00}$ is sound, since then only that byte is inspected and $\Pi_{\mathrm{len}}$ holds; so the batch contains a sound test and by Lemma 3(a) the test $R$ of largest sample mean is sound. By Lemma 15 the sound class is tight, so Lemma 3(b) classifies every other test of the batch against $R$, determining the sound set exactly.

Any sound mask other than $M_0$ has $\mathit{pl} \ge 1$, which forces $P_4[14] = \mathit{pl}$; since $P_4[14]$ is fixed in this enumeration, at most one such mask exists, so the sound set is $\{R\}$ or $\{R, X\}$. In the first case $R = M_0$, as $M_0$ is sound. In the second, run one further test on $R'$, obtained from $R$ by modifying $\Delta[14]$, and classify it against $R$: a mask with $\mathit{pl} = 0$ never inspects $P_4[14]$ and stays sound, while one with $\mathit{pl} \ge 1$ acquires $P_4[14] \ne \mathit{pl}$ and becomes unsound in every session, so $R = M_0$ if $R'$ is sound and $X = M_0$ otherwise. Either way $M_0$ is identified and $P^{*}[15] = \Delta[15]$, at a cost of $2^8 + 2$ tests.

The remaining fifteen bytes follow by fifteen applications of Lemma 12 with $k = 1,\dots,15$, whose statement is phrased in the receiver-independent predicate $\Pi_{\mathrm{strict}} \wedge (\mathit{pl} \ge 1)$: in each enumeration exactly one mask satisfies it in every session and is therefore the unique sound one, so Lemma 3(a) identifies it as the test of largest sample mean, at $2^8$ tests each. $\square$

<span style="color:#87A878">**Theorem 17 ($\mathsf{R}_{\mathrm{strict}}$ receivers).**</span> *Assume (H1)–(H6). Let $\varepsilon \in (0,1)$, put $M = 16 \cdot 2^8 + 2$ and let $L'$ be as in Lemma 15 for that $M$ and $\varepsilon$. Then a TLS 1.0 receiver of family $\mathsf{R}_{\mathrm{strict}}$ with $t = 20$, $b = 16$ is broken by an IV-oblivious attack using $q \le L' M$ sessions, with success probability at least $1 - \varepsilon - q(2^{-158} + \epsilon_{\mathrm{prf}} + \epsilon_{\mathrm{prp}})$.*

<span style="color:#808080">*Proof.*</span>  Combine Lemmas 15 and 16 at this $M$, which matches the test count of Lemma 16. The records injected are those of Section 1.4.2, so the adversary is IV-oblivious and Definition 5 supplies the four-block form needed against a chained IV. The forgery accounting is that of Theorem 7, and applies only to the sound branch, where a MAC is computed at all; the bound there does not depend on the freshness of the injected MAC input, so it transfers unchanged. $\square$

<span style="color:#87A878">**Remark 3 (the $\Pi_{\mathrm{len}}$ families are not covered).**</span> Neither $\mathsf{R}_{\mathrm{len}}$ nor $\mathsf{R}_{\mathrm{len}\text{-}\mathrm{mac}}$ is reached by the arguments above, and for the same underlying reason: $\Pi_{\mathrm{len}}(P)$ depends only on whether $\mathit{pl} \le |P| - 1 - t$, a threshold on the single byte $P_4[15]$, so the branch taken conveys no information about any other byte.

For $\mathsf{R}_{\mathrm{len}}$ the separation of Lemma 15 still holds with $\Pi_{\mathrm{strict}}$ replaced by $\Pi_{\mathrm{len}}$, since the failing branch still computes no MAC; what fails is Lemma 16, at its first step. That step argued that at most one sound mask beyond the $\mathit{pl} = 0$ one exists, using the fact that $\Pi_{\mathrm{strict}}$ inspects $P_4[14]$. Under $\Pi_{\mathrm{len}}$ that byte is never inspected, and exactly $44$ of the $256$ masks in the enumeration are sound, namely those with $\mathit{pl} \le 43$; the oracle therefore locates $P^{*}[15]$ only up to the $44$-element set $P^{*}[15] \oplus \{0,\dots,43\}$, and yields nothing at all about the other bytes.

For $\mathsf{R}_{\mathrm{len}\text{-}\mathrm{mac}}$ a MAC is always computed, over $\mathrm{strip}(P)$ when $\mathit{pl} \le 43$ and over $\mathrm{strip}_0(P)$ otherwise, so by Lemma 1 the cost is $N(56 - \mathit{pl}) = 4$ for $1 \le \mathit{pl} \le 43$ and $5$ for $\mathit{pl} = 0$ or $\mathit{pl} \ge 44$. The fast branch is thus again a threshold on $P_4[15]$ alone, and carries the same information as in the previous paragraph.

Nothing in this document establishes plaintext recovery against either family, and Theorems 14 and 17 must not be read as covering them.
