# Proof plan: plaintext recovery against TLS 1.2 CBC (MEE-TLS-CBC)

Source: N. J. AlFardan and K. G. Paterson, *Lucky Thirteen: Breaking the TLS and DTLS Record Protocols*, 27 February 2013 (`TLStiming.pdf`). Section references below are to that paper.

## Standing conventions

Fix throughout: block size $b = 16$ bytes (AES), tag length $t = 20$ bytes (HMAC-SHA-1), header length $h = 13$ bytes (8-byte `SQN` + 5-byte `HDR`), explicit IV (TLS 1.2). These are the values under which the efficient attack exists; §4.3 handles $t \in \{16, 32\}$ and the plan flags where the argument degrades. All lengths are in bytes. Write $x \,\|\, y$ for concatenation, $\langle p \rangle^{n}$ for the byte with value $p$ repeated $n$ times, and $B = [B_0 B_1 \cdots B_{b-1}]$ for the bytes of a block $B$.

The central structural fact to state before anything else, and to return to in §3.6: Paterson, Ristenpart and Shrimpton (ASIACRYPT 2011, ref. [28]) **proved** that MEE-TLS-CBC achieves Length-Hiding Authenticated Encryption, in a model that already includes the full padding encoding, assuming decryption reveals nothing but the fact of failure. The paper under study says so explicitly on p. 4 and states that its attacks "do not contradict the result of [28], but instead relativize its applicability to practice." So the theorem you are aiming at is **false** in the standard model. The entire content of §1 below is the construction of the *one* model extension — a leakage-augmented decryption oracle — that makes it true, and §3.6 is the argument that this extension is not only sufficient but necessary.



# Section 1 : Defining TLS 1.2 CBC mode cryptographically

## 1.1 Syntax

Define a stateful length-hiding authenticated encryption scheme $\Pi = (\mathsf{Gen}, \mathsf{Enc}, \mathsf{Dec})$ with the state carried by the sequence number. Adopt the syntax of [28] verbatim so that the impossibility direction in §3.6 composes without translation.

$\mathsf{Gen}(1^\kappa)$ returns $K = (K_e, K_a)$ with $K_e$ a block-cipher key and $K_a$ a MAC key. Sender and receiver each keep an 8-byte counter $\mathrm{SQN}$, initialised to $0$ and incremented per record. $\mathsf{Enc}$ takes a record $R \in \{0,1\}^{8 \cdot |R|}$ of arbitrary byte length $\ge 0$ and a 5-byte header $\mathrm{HDR}$; $\mathsf{Dec}$ takes $\mathrm{HDR} \,\|\, C$ and returns a record or the distinguished symbol $\bot$.

## 1.2 Components

Let $E : \{0,1\}^{\kappa} \times \{0,1\}^{8b} \to \{0,1\}^{8b}$ be the block cipher with inverse $D$, modelled as a PRP. Let $\mathrm{HMAC}\text{-}H$ be the MAC with $\kappa$-byte key and $t$-byte tag, modelled as SUF-CMA. Both assumptions are the ones [28] uses, which matters for §3.6.

## 1.3 The encoding step

This is the part that no generic MAC-then-encrypt abstraction captures, and getting it exactly right is the whole reason the attack exists. Define

$$\mathsf{Encode}(R, T) = R \,\|\, T \,\|\, \langle p \rangle^{p+1}$$

where the padding byte value $p$ satisfies $|R| + t + p + 1 \equiv 0 \pmod b$ and $0 \le p \le 255$. The minimal legal choice is $p_{\min} = b - 1 - \big((|R| + t) \bmod b\big)$, and every $p = p_{\min} + jb \le 255$ for integer $j \ge 0$ is also legal. Two properties to record as a numbered remark, because both are load-bearing later: **at least one** padding byte is always present (so zero-length padding is never produced by a legitimate sender, yet is what the RFC tells a receiver to assume on failure), and padding **may span several blocks** ; receivers are required to support removal of up to 256 padding bytes. The distinguishing attack of §2.1 lives entirely off this second property.

## 1.4 Encryption

$\mathsf{Enc}_K(\mathrm{HDR}, R)$: compute $T \leftarrow \mathrm{HMAC}_{K_a}(\mathrm{SQN} \,\|\, \mathrm{HDR} \,\|\, R)$, set $P \leftarrow \mathsf{Encode}(R,T)$ and parse it into blocks $P_1 \cdots P_n$, draw $C_0 \leftarrow \{0,1\}^{8b}$ uniformly as the explicit IV, and output $\mathrm{HDR} \,\|\, C_0 \,\|\, C_1 \,\|\, \cdots \,\|\, C_n$ where $C_j = E_{K_e}(P_j \oplus C_{j-1})$. Increment $\mathrm{SQN}$. Note explicitly that $\mathrm{SQN}$ is authenticated but **not transmitted** : the receiver supplies its own copy : since the attacker's ability to submit forged records without touching $\mathrm{SQN}$ depends on it.

## 1.5 Decryption : the RFC-compliant depad, stated as an algorithm

Write $\mathsf{Dec}$ out as numbered pseudocode rather than prose. This is §2 p. 5 of the paper made precise, and every branch is referenced later.

1. Reject unless $|C| - b$ is a positive multiple of $b$ and $|C| - b \ge t + 1$ (sanity check: room for a zero-length record, a tag, and one padding byte).
2. $P_j \leftarrow D_{K_e}(C_j) \oplus C_{j-1}$ for $j = 1, \dots, n$; set $P \leftarrow P_1 \,\|\, \cdots \,\|\, P_n$ and $\ell_P \leftarrow nb$.
3. $\mathit{padlen} \leftarrow P[\ell_P - 1]$ interpreted as an integer in $[0,255]$.
4. Say the padding is **well-formed** iff $\ell_P \ge \mathit{padlen} + 1 + t$ **and** the final $\mathit{padlen}+1$ bytes of $P$ all equal $\mathit{padlen}$.
5. If well-formed: $R \leftarrow P[0 \,..\, \ell_P - \mathit{padlen} - t - 2]$ and $T \leftarrow P[\ell_P - \mathit{padlen} - t - 1 \,..\, \ell_P - \mathit{padlen} - 2]$.
6. Otherwise (**the RFC 4346/5246 branch**): assume zero-length padding ; $T \leftarrow$ the last $t$ bytes of $P$, $R \leftarrow P[0 \,..\, \ell_P - t - 1]$.
7. Return $R$ if $\mathrm{HMAC}_{K_a}(\mathrm{SQN} \,\|\, \mathrm{HDR} \,\|\, R) = T$, else $\bot$.

Step 6 is the vulnerability. It exists to defeat the Canvel et al. attack [6] by forcing a MAC check on every path, and it succeeds at that ; the *outcome* is always $\bot$ and carries no information. What it cannot hide is that the MAC is computed over a string whose length depends on which branch was taken.

## 1.6 The leakage function

Define $\lambda(P)$, the byte-length of the string passed to HMAC:

$$\lambda(P) = \begin{cases} h + \ell_P - t - 1 - \mathit{padlen}(P) & \text{if the padding is well-formed,} \\ h + \ell_P - t & \text{otherwise.} \end{cases}$$

Then define the cost function, from §2.1 p. 6, counting compression-function evaluations of $H$ on an $\ell$-byte HMAC input:

$$\mathsf{cost}(\ell) = \left\lceil \frac{\ell - 55}{64} \right\rceil + 4 .$$

Derive it rather than quoting it ; the derivation is two lines and makes the constant 55 non-mysterious. The inner hash consumes $64 + \ell$ bytes (the ipad-XORed key block plus the message) plus at least 9 bytes of Merkle–Damgård strengthening (one $\texttt{0x80}$ byte and an 8-byte length field), rounded up to a multiple of 64; the outer hash consumes $64 + t + 9 \le 128$ bytes, i.e. exactly 2 blocks for any $t \le 55$. Sanity-check the formula at $\ell = 55 \mapsto 4$, $\ell = 56 \mapsto 5$, $\ell = 119 \mapsto 5$, $\ell = 120 \mapsto 6$. The point to emphasise, and the reason this paper admits a *proof* rather than only measurements, is that $\mathsf{cost}$ is an exact closed form, not an empirical fit.

## 1.7 Two leakage models

**Model A (noiseless).** The decryption oracle returns $\big(\bot, \mathsf{cost}(\lambda(P))\big)$. Everything in Section 3 except §3.5 is proved here, and the results are exact rather than asymptotic.

**Model B (noisy).** The oracle returns $(\bot, \tau)$ with $\tau = c_0 \cdot \mathsf{cost}(\lambda(P)) + \eta$, where $c_0 > 0$ is the per-compression cost and $\eta$ is drawn from a fixed noise distribution, independently per query. Assume $\eta$ is sub-Gaussian with parameter $\sigma$. This is the honest abstraction of network jitter; the paper supplies experiments (§5) and the empirical value $L = 2^7$ but no bound, so §3.5 is yours to supply.

## 1.8 The session model

TLS treats every decryption error as fatal (§2 p. 5), so **one decryption query destroys the session**. Formalise the Canvel et al. multi-session setting [6] as the paper does on p. 8: the adversary interacts with $q$ independent sessions, each with fresh keys and fresh IVs, each encrypting the *same* record $R^\ast$ at the *same* record position, and is allowed exactly one decryption query per session. State this as an explicit hypothesis of Theorem 2, not as a footnote ; it is the one genuinely strong assumption in the whole development.

## 1.9 The plaintext-recovery game

$\mathbf{Exp}^{\mathrm{PR}}_{\Pi, \mathcal{A}}$: sample $q$ independent key pairs; encrypt $R^\ast$ once per session and hand the adversary all $q$ ciphertexts; give the adversary the Model-A (or Model-B) decryption oracle subject to the one-query-per-session rule; the adversary outputs $\hat{P}$ and wins iff $\hat{P} = P^\ast$, where $P^\ast$ is the target plaintext block. Define $\mathbf{Adv}^{\mathrm{PR}}_{\Pi}(\mathcal{A}) = \Pr[\mathcal{A} \text{ wins}]$. Note that unlike an indistinguishability advantage this is not normalised against a $1/2$ baseline; the trivial bound is $2^{-8b}$.



# Section 2 : Building the cryptographic attacker

## 2.1 Warm-up: the distinguishing adversary

Do this first. It is a single query, needs no session model, and it exercises the leakage machinery of §1.6 in isolation, so if the case analysis is wrong it shows up here where it is cheap to fix. This is §3 of the paper.

$\mathcal{A}_{\mathrm{dist}}$ submits $M_0 = (\text{32 arbitrary bytes}) \,\|\, \langle \texttt{0xFF} \rangle^{256}$ and $M_1 = (\text{287 arbitrary bytes}) \,\|\, \texttt{0x00}$, both exactly 288 bytes, so both fill 18 blocks and both end on a block boundary : hence $T \,\|\, \mathit{pad}$ occupies blocks disjoint from $M_d$. On receiving $\mathrm{HDR} \,\|\, C$ it truncates to the IV plus the first 288 bytes of non-IV ciphertext, producing $C'$, and submits $\mathrm{HDR} \,\|\, C'$ for decryption. It outputs $0$ if the observed cost is $4$ and $1$ otherwise.

Verify the arithmetic in the writeup, since it is the template for §2.3. With $\ell_P = 288$: under $d = 0$ the trailing $\texttt{0xFF}$ bytes form well-formed padding with $\mathit{padlen} = 255$, so $\lambda = 13 + 288 - 20 - 1 - 255 = 25$ and $\mathsf{cost}(25) = 4$; under $d = 1$ the single $\texttt{0x00}$ is well-formed padding with $\mathit{padlen} = 0$, so $\lambda = 13 + 288 - 20 - 1 - 0 = 280$ and $\mathsf{cost}(280) = \lceil 225/64 \rceil + 4 = 8$. A gap of four compression functions, from one query.

## 2.2 Attack geometry

Let $C^\ast$ be the target ciphertext block and $C'$ its predecessor (possibly the IV), so that $P^\ast = D_{K_e}(C^\ast) \oplus C'$. For a 16-byte mask $\Delta$ define the forged record

$$C^{\mathrm{att}}(\Delta) = \mathrm{HDR} \,\|\, C_0 \,\|\, C_1 \,\|\, C_2 \,\|\, (C' \oplus \Delta) \,\|\, C^\ast$$

with $C_0$ the IV and $C_1, C_2$ arbitrary (four non-IV blocks, so $\ell_P = 64$, which passes step 1 of §1.5). The decrypted final block is

$$P_4 = D_{K_e}(C^\ast) \oplus (C' \oplus \Delta) = P^\ast \oplus \Delta,$$

so the adversary steers the trailing plaintext bytes at will while the block cipher key stays out of reach. Record that $P_3 = D_{K_e}(C' \oplus \Delta) \oplus C_2$ is *not* controlled and behaves pseudorandomly as $\Delta$ varies ; §3.3 needs this.

## 2.3 The three cases

With $\ell_P = 64$, $t = 20$, $h = 13$, exactly one of the following holds.

- **Case 1** : $P_4$ ends in $\texttt{0x00}$. Well-formed padding, $\mathit{padlen} = 0$, one byte removed, $|R| = 43$, so $\lambda = 56$.
- **Case 2** : $P_4$ ends in well-formed padding of length $\ge 2$, i.e. $\mathit{padlen} = p$ with $1 \le p \le 43$. Then $|R| = 43 - p \le 42$ and $\lambda = 56 - p \le 55$.
- **Case 3** : anything else. The RFC branch (step 6) applies, $|R| = 44$, so $\lambda = 57$.

The upper limit $p \le 43$ is forced by the underflow check in step 4 ($\mathit{padlen} + 1 + t \le 64$); values $p \ge 44$ fall into Case 3, not Case 2. State this, because a reader will otherwise expect $p \le 255$.

## 2.4 The adversary $\mathcal{A}_{\mathrm{PR}}$

Define a subroutine $\mathsf{Probe}(\Delta)$: open a fresh session, submit $C^{\mathrm{att}}(\Delta)$, return $\mathsf{true}$ iff the observed cost is 4. By §3.2 this is exactly a test for Case 2.

**Phase 1 : the last two bytes, $\le 2^{16}$ probes.** Fix $\Delta_0, \dots, \Delta_{13} = \texttt{0x00}$ and enumerate $(\Delta_{14}, \Delta_{15}) \in \{0,\dots,255\}^2$ until $\mathsf{Probe}$ returns true. The intended hit is $\Delta_{14} = P^\ast_{14} \oplus \texttt{0x01}$, $\Delta_{15} = P^\ast_{15} \oplus \texttt{0x01}$, which makes $P_4$ end in $\texttt{0x01}\,\|\,\texttt{0x01}$.

**Phase 1b : disambiguation, $\le 14$ extra probes.** Do not skip this; the paper disposes of it in one parenthesis on p. 8 but it is a genuine correctness obligation. A hit may also arise from a longer padding pattern (for instance if $P^\ast_{13} = \texttt{0x02}$ and the mask happens to set bytes 14 and 15 to $\texttt{0x02}$ as well). On each hit, re-probe with $\Delta'$ equal to $\Delta$ except in byte 13. If the result is still Case 2, the pattern had length exactly 2 and byte 13 was irrelevant; if it flips, the pattern was longer. Specify the rule precisely and fold its failure probability into $\nu$ in §3.3.

**Phase 2 : the remaining 14 bytes, $\le 2^8$ probes each.** For $i = 2, 3, \dots, 15$ in turn, with $P^\ast_{16-i}, \dots, P^\ast_{15}$ already known, set $\Delta_j = P^\ast_j \oplus i$ for every $j \in \{16-i, \dots, 15\}$ : forcing those bytes of $P_4$ to the value $i$ ; and enumerate $\Delta_{15-i}$ over its 256 values. Exactly one value completes well-formed padding of length $i+1 \ge 2$, giving Case 2, and then $P^\ast_{15-i} = \Delta_{15-i} \oplus i$. This phase is Vaudenay's original padding-oracle attack [37] unchanged.

**Output** $\hat{P} = P^\ast$.

Worst-case query count $2^{16} + 14 \cdot 2^8 + 14 < 2^{16.1}$, hence the same number of sessions; expected count roughly $2^{15} + 14 \cdot 2^7$.

## 2.5 Variants worth a remark each

Partially-known plaintext (p. 8): one known byte out of the last two collapses Phase 1 from $2^{16}$ to $2^8$, giving $15 \cdot L \cdot 2^8$ sessions overall. Restricted alphabets: Base64-encoded cookie or credential bytes take Phase 2 to $2^6$. Lucky 13 + BEAST (p. 8): browser-resident malware opens the sessions itself and pads the request so that each target block holds exactly one unknown cookie byte, reaching $\approx 2^{13}$ sessions per byte at $L = 2^7$. These do not need separate theorems ; one corollary with a table of query counts is enough.



# Section 3 : Proving the attacker recovers the plaintext

## 3.1 Lemma 1 (encoding length)

For every $\Delta$ and every key, the length of the string submitted to HMAC during decryption of $C^{\mathrm{att}}(\Delta)$ is $56$ in Case 1, at most $55$ in Case 2, and $57$ in Case 3. Immediate from §1.5 and §1.6 by substituting $\ell_P = 64$, $t = 20$, $h = 13$; the proof is three lines of arithmetic and should be written out, because Lemma 2 is entirely a corollary of these three numbers.

## 3.2 Lemma 2 (leakage separation) : the crux

$\mathsf{cost}(\lambda) = 4$ in Case 2 and $\mathsf{cost}(\lambda) = 5$ in Cases 1 and 3. Proof: $\mathsf{cost}$ is constant on $[\,\cdot\,, 55]$ and steps at 56, and Lemma 1 places Case 2 at or below 55 and Cases 1 and 3 strictly above it.

Follow it with the sensitivity remark, which is the paper's own punchline (p. 9) and the cleanest way to show a reader that the result is arithmetic rather than accidental. Had the header been $h = 12$, Case 1 would give $\lambda = 55$ and hence cost 4, so the oracle would detect well-formed padding of *any* length, a single $\texttt{0x00}$ would suffice, and the whole attack would cost $2^8$ instead of $2^{16}$. Thirteen is lucky; twelve would have been luckier. Conversely the attack needs $t = 20$: for $t = 16$ or $t = 32$ the same computation puts the threshold at padding length $\ge 6$, Phase 1 becomes $2^{48}$, and only the partially-known-plaintext variants stay attractive (§4.3, p. 9).

## 3.3 Lemma 3 (reduction to a padding oracle)

This is the pivot of the whole proof: it converts a timing attack into a classical padding-oracle attack, after which nothing about timing appears again.

**Statement.** In Model A, $\mathsf{Probe}$ implements the oracle $\mathcal{O}_{\mathrm{pad}}(C) = 1 \iff$ the decryption of $C$ ends in well-formed padding of length $\ge 2$, except on a bad event $\mathsf{Bad}$ with

$$\Pr[\mathsf{Bad}] \le \mathbf{Adv}^{\mathrm{prp}}_{E}(\mathcal{B}) + \mathbf{Adv}^{\mathrm{suf\text{-}cma}}_{\mathrm{HMAC}}(\mathcal{C}) + \frac{q^2}{2^{8b+1}} + \nu .$$

**Game hops.** $G_0$ is the real game. $G_1$ replaces $E_{K_e}$ by a uniform random permutation, at cost $\mathbf{Adv}^{\mathrm{prp}}_E(\mathcal{B})$ ; $\mathcal{B}$ simulates the whole experiment, which is efficient because the adversary is. $G_2$ aborts if any of the $q$ forgeries verifies, at cost $\mathbf{Adv}^{\mathrm{suf\text{-}cma}}_{\mathrm{HMAC}}(\mathcal{C})$; this is what licenses the standing claim that every query returns $\bot$ and so the *outcome* is information-free. $G_3$ aborts on a block collision inside CBC, at the birthday cost $q^2 / 2^{8b+1}$. In $G_3$ the observed cost is a deterministic function of the three cases, which is Lemma 2.

**The ambiguity term $\nu$.** Analyse Phase 1 exactly rather than by a union bound, which here would be vacuous. Because $\Delta_0, \dots, \Delta_{13}$ are held at $\texttt{0x00}$ throughout Phase 1, the low 14 bytes satisfy $P_4[j] = P^\ast[j]$ for $j \le 13$ and do **not** vary with the probe. Consequently a well-formed pattern of length $k+1$ with $2 \le k \le 15$ requires $P^\ast[15-k], \dots, P^\ast[13]$ all to equal $k$ ; a fixed property of the unknown target, not an event over the probe ; together with one specific value of $(\Delta_{14}, \Delta_{15})$. So each $k \in \{1, \dots, 15\}$ contributes **at most one** Case-2 hit, and the hits for distinct $k$ occur at distinct masks since they force $(P_4[14], P_4[15]) = (k,k)$. A pattern with $k \ge 16$ additionally requires all of $P^\ast[0], \dots, P^\ast[13]$ to equal the single value $k$, which can hold for at most one $k$, and then also $k - 15$ prescribed bytes of the pseudorandom $P_3$, contributing at most $2^{-8}$ over the coins of $G_1$.

Phase 1b resolves this completely, which is why $\nu$ ends up tiny rather than merely small. Flipping byte 13 of the mask leaves a length-2 pattern intact ; byte 13 is not part of it ; and destroys every pattern of length $\ge 3$, since byte 13 *is* part of those and the last byte still reads $k \ne 0$, so the result is Case 3 rather than a different Case 2. Hence Phase 1b identifies $k = 1$ with certainty among in-block hits, at most 15 hits arise, and $\nu \le 2^{-8}$ from the $P_3$-dependent case alone. Write the length-2-versus-length-3 boundary out explicitly; it is the only step where the disambiguation rule could plausibly fail and it is worth showing that it does not.

## 3.4 Lemmas 4 and 5 (phase correctness) and Theorem 2

**Lemma 4.** Conditioned on $\neg\mathsf{Bad}$, Phase 1 followed by Phase 1b outputs $(P^\ast_{14}, P^\ast_{15})$ after at most $2^{16} + 14$ probes. Existence: the intended mask is in the enumerated set. Uniqueness up to Phase 1b: argue over the at most 15 competing in-block patterns.

**Lemma 5.** Conditioned on $\neg\mathsf{Bad}$ and on correct knowledge of the last $i$ bytes, iteration $i$ of Phase 2 outputs $P^\ast_{15-i}$ after at most $2^8$ probes. Here uniqueness is exact and needs no disambiguation, since only one byte of $\Delta$ varies and the target value $i$ is fixed ; worth stating as the reason Phase 2 is cheaper per byte than Phase 1, not merely shorter.

**Theorem 2 (main).** In Model A, under the multi-session hypothesis of §1.8, $\mathcal{A}_{\mathrm{PR}}$ runs in time $O(2^{16})$, consumes at most $2^{16} + 14\cdot 2^8 + 14$ sessions and one decryption query each, and

$$\mathbf{Adv}^{\mathrm{PR}}_{\text{MEE-TLS-CBC}}(\mathcal{A}_{\mathrm{PR}}) \;\ge\; 1 - \mathbf{Adv}^{\mathrm{prp}}_{E}(\mathcal{B}) - \mathbf{Adv}^{\mathrm{suf\text{-}cma}}_{\mathrm{HMAC}}(\mathcal{C}) - \frac{q^2}{2^{8b+1}} - \nu .$$

Proof: Lemma 3 to replace the timing oracle by $\mathcal{O}_{\mathrm{pad}}$, then Lemmas 4 and 5 by induction over the 16 byte positions. Note that the recovered $P^\ast$ is the *encoded* plaintext block; if it is not the final block of the record it is a record block outright, and if it is, strip $T \,\|\, \mathit{pad}$ ; say which, so the theorem statement is unambiguous about what "recovers" means.

**Theorem 1 (distinguishing).** State and prove the §2.1 adversary in the same framework: one query, advantage $\ge 1 - \Pr[\mathsf{Bad}]$. It is a corollary of Lemma 2 and makes the paper readable.

## 3.5 Theorem 3 (the noisy model) : optional but the honest version

The paper gives only experiments here (§5), so this section is entirely yours. In Model B, run $\mathsf{Probe}$ $L$ times per candidate $\Delta$ and threshold the sample median (the paper reports that medians and percentiles beat means on its skewed, long-tailed data, §5.2). With $\eta$ sub-Gaussian of parameter $\sigma$, Hoeffding bounds the per-candidate error by $\exp(-L c_0^2 / 8\sigma^2)$, and a union bound over the $2^{16} + 14 \cdot 2^8$ candidates gives

$$L = O\!\left( \frac{\sigma^2}{c_0^2} \log \frac{2^{16}}{\epsilon} \right)$$

for overall failure probability $\epsilon$, at a total cost of $L \cdot (2^{16} + 14\cdot 2^8)$ sessions. Compare the resulting number against the paper's measured $L = 2^7$ at $c_0 \approx$ one SHA-1 compression on a 1.87 GHz core (§5.4) : a plan-level cross-check that the bound is not vacuous. Flag the modelling gap honestly: independence of $\eta$ across queries is an idealisation, and real jitter is correlated.

## 3.6 Proposition (the leakage model is necessary, not convenient)

Close the argument by showing the extension in §1.7 is forced. Cite [28]: in the model where decryption returns only $\bot$, MEE-TLS-CBC is LH-AE secure under the same PRP and SUF-CMA assumptions used above, so no adversary whatsoever achieves non-negligible PR advantage there. Hence Theorem 2 is tight in the precise sense that removing the cost component of the oracle's output destroys it. This is also what makes the result a statement about *implementations* of TLS 1.2 CBC rather than about the abstract construction : and it is the sentence a reviewer will look for.

## 3.7 Scope, stated as limitations

Three claims the theorem does **not** make, all to be stated plainly. It covers CBC ciphersuites only ; the AEAD ciphersuites of TLS 1.2 (GCM, CCM) are untouched. It is proved for $t = 20$; at $t \in \{16, 32\}$ Phase 1 costs $2^{48}$ and only the partially-known-plaintext corollaries remain practical. And it assumes the RFC 4346/5246 depad branch of step 6 ; GnuTLS removes $\mathit{padlen}+1$ bytes instead (§6.1), which needs a different case analysis and yields a different, in fact larger, timing signal.



# Appendix: a suggested ordering, and what to cite

Write and verify §2.1/Theorem 1 before anything else; it is one query and it will catch arithmetic errors in Lemma 1 immediately. Then Lemmas 1–3, then Theorem 2, then Theorem 3 last since it is the only part not underwritten by the source. §3.6 should be drafted early even though it appears late, because it determines how §1.7 must be phrased.

Beyond `TLStiming.pdf` you will need [28] Paterson–Ristenpart–Shrimpton, *Tag size does matter: attacks and proofs for the TLS record protocol*, ASIACRYPT 2011 ; for the syntax, the LH-AE definition and §3.6; [37] Vaudenay, EUROCRYPT 2002 ; Phase 2 is his attack; [6] Canvel–Hiltgen–Vaudenay–Vuagnoux, CRYPTO 2003 ; the multi-session model of §1.8; [1] AlFardan–Paterson, NDSS 2012 ; the DTLS timing-amplification techniques; and RFC 5246 §6.2.3.2 for the depad prescription quoted in §1.5.

One alternative worth weighing before committing: the **DTLS** version of the attack (§4.4, p. 9) runs in a *single* session, because DTLS errors are non-fatal. That removes the multi-session hypothesis of §1.8 ; the only strong assumption in the development ; and replaces the error-message channel with the amplification technique of [1]. If the goal is the cleanest possible theorem rather than a statement specifically about TLS, DTLS is the easier target and the surrounding machinery is identical.




