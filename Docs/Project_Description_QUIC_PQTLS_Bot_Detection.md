# Project Description
## Next-Generation Protocol Fingerprinting for Robust Bot Detection

**Student:** Basel Ali Khan
**Domain:** Cybersecurity / Network Security / Applied Machine Learning

---

## 1. Overview

This project studies whether two internet protocol shifts that happened in 2024-2026 — the rollout of post-quantum TLS key exchange and growing QUIC/HTTP-3 adoption — can be used as new, reliable signals for detecting automated bot traffic on websites, and builds a working system that does exactly that in real time.

In one sentence: **real browsers now handshake differently than most bots do, in ways nobody has formally measured as a detection signal yet — this project measures it, and builds a live system around it.**

---

## 2. Background and Motivation

### 2.1 The existing problem
Websites have always needed to tell real human visitors apart from automated bots — scrapers, credential-stuffing scripts, inventory hoarders, content thieves. One of the most effective ways to do this without inconveniencing real users is TLS fingerprinting: every piece of software that makes an HTTPS connection has a distinctive "handshake shape" (which encryption methods it offers, in what order, which extensions it includes). Techniques like JA3 and JA4 turn this shape into a fingerprint, and commercial bot-detection services (Cloudflare, Akamai, DataDome, and others) rely on it heavily today.

### 2.2 What's changed recently
Two things shifted the ground under this technique, both within the last two years:

- **Post-quantum cryptography.** Because sufficiently powerful quantum computers could eventually break current encryption, browser vendors began rolling out "hybrid" key exchange methods that combine classical and quantum-resistant cryptography. Chrome enabled this by default in April 2024, Firefox in November 2024. As of early 2026, this new key-exchange data (specifically a method called X25519MLKEM768) appears in the majority of real browser handshakes.
- **QUIC and HTTP/3.** A newer, faster transport protocol that most modern browsers use automatically when a server supports it, running over UDP instead of TCP, with its own distinct handshake behavior separate from classic TLS.

Real, mainstream browser software has adopted both of these. Most bot frameworks, scraping libraries, and automation tools have not caught up — either because their underlying TLS libraries are older, or because nobody has prioritized adding support for signals nobody is yet checking for.

### 2.3 Why this matters right now
This creates a live, current, largely unexamined detection opportunity — but also, if left unaddressed, a live blind spot: as more legitimate traffic naturally carries these markers, their *absence* becomes an increasingly reliable tell for automated traffic, right up until bot tooling catches up and starts spoofing them too. Neither side of that story — using it as a signal, or studying how fast it can be evaded — has a rigorous published study behind it yet.

---

## 3. Problem Statement

Current bot-detection research and commercial systems evaluate TLS and HTTP-level fingerprints, but none rigorously evaluates whether post-quantum key-share presence and QUIC/HTTP-3 handshake behavior can meaningfully improve detection accuracy, nor how quickly a motivated attacker could adapt to defeat that advantage. This leaves both website operators and the research community without evidence-based guidance on a signal that is already quietly emerging in real-world traffic.

---

## 4. Objectives

1. Empirically measure whether adding post-quantum key-share presence and QUIC/HTTP-3 handshake features to a bot-detection classifier improves accuracy over classical TLS/HTTP fingerprinting alone.
2. Quantify how much of that improvement survives when a sophisticated bot deliberately attempts to replicate these new signals (evasion resistance).
3. Design and build a working, real-time detection system that uses these findings in practice — not just a static analysis, but a live proxy that scores and can block suspicious connections as they happen.
4. Produce a publishable, reproducible methodology and result set, and a system architecture substantial enough to support a patent-style system-and-method claim.

---

## 5. Proposed Approach (conceptual, not implementation detail)

The project has two halves that feed each other:

**Measurement half:** Build a controlled test environment (a small self-hosted website), generate labeled traffic from real browsers and from bots at increasing levels of sophistication, capture and fingerprint every connection, and train machine learning classifiers to compare detection accuracy with and without the new protocol signals. This produces the core empirical result.

**Systems half:** Take what the measurement half learns and turn it into a live, deployed detection service — a proxy that inspects incoming connections in real time, scores them, and makes an allow/block decision on the spot. This is what makes the project a working system rather than only a research finding, and it's what gets demonstrated live.

---

## 6. Scope

**In scope:**
- Controlled, self-hosted lab environment (not testing against real production websites without consent — this matters both ethically and legally)
- TLS and QUIC handshake-level features only (no payload inspection, no user behavioral biometrics like mouse movement — keeping the signal set focused and the contribution clean)
- A defined, honest set of bot sophistication tiers, not an exhaustive simulation of every possible bot in existence
- A working real-time detection proxy as a functional prototype, not a hardened production-grade commercial product

**Out of scope:**
- Testing against real commercial bot-detection systems' internal logic (not accessible, and not necessary for the core contribution)
- Claiming this replaces existing fingerprinting methods — it's an addition to, not a replacement for, established techniques like JA4
- Large-scale internet traffic collection (ethically and practically outside a semester project's reach; the controlled-lab methodology is the same approach used in comparable recent published work)

---

## 7. Expected Outcomes and Deliverables

By the end of the project, this should exist and work end-to-end:

1. A documented, reproducible dataset of labeled human and bot traffic, captured with full protocol-level fingerprint detail.
2. A trained classifier with a clearly reported, honest comparison: how much (if any) detection improvement the new signals provide over classical fingerprinting alone.
3. An evasion-resistance analysis showing how that advantage holds up against an adaptive attacker — reported honestly even if the answer is "partially."
4. A working, live detection proxy that a panel can watch classify and block traffic in real time during a demonstration.
5. A dashboard visualizing live detection activity and the baseline-vs-enhanced comparison.
6. A written paper suitable for submission to a Scopus-indexed conference or security-adjacent workshop, co-authored with your guide.
7. A scoped, defensible provisional patent claim covering the real-time detection system and method, if you and your guide choose to pursue it.
8. A clean, professional public GitHub repository suitable for your portfolio and recruiter visibility, alongside ModelGuard and your AI Media Intelligence System.

---

## 8. What Makes This Novel

This isn't framed as novel by assertion — it was checked against current literature before being chosen. As of mid-2026:
- Existing academic TLS/HTTP fingerprinting work (including a February 2026 paper achieving strong bot-detection results) explicitly names extending to HTTP/3 as unresolved future work.
- Existing QUIC fingerprinting research addresses a different problem entirely — identifying which website someone is visiting (a privacy concern), not distinguishing bots from humans.
- Discussion of post-quantum TLS key shares as a detection signal exists only at the industry-blog level as of this project's planning, with no formal academic study found evaluating it empirically.

This project sits precisely in that gap: a measured, evaluated, systems-backed answer to a question the field has only just started asking.

---

## 9. Significance

For website operators and security teams, this offers evidence-based guidance on a signal that's already appearing in their traffic logs whether they're using it or not. For the research community, it's a concrete, reproducible methodology others can build on or challenge. For you, it demonstrates the combination that matters most for both an S grade and recruiter conversations: real systems engineering, applied security research, and a working deployed artifact — not just a trained model or a paper with no product behind it.

---

## 10. Success Criteria

The project succeeds if, by the end of the semester:
- The empirical comparison produces a clear, honestly-reported result (whether the new signals help a little, a lot, or not much — a rigorous negative result is still a valid, defensible outcome)
- The live detection system runs reliably end-to-end for a demo
- The write-up is complete and submitted to a real venue
- Your guide is satisfied the healthcare-adjacent domain requirement is met through the general AI-security framing agreed on, or has explicitly signed off on the domain shift

---

## 11. Honest Limitations (stated upfront, not discovered later)

- The dataset is lab-generated, not organic internet-scale traffic — a known, standard, and defensible limitation for a project at this scope, not a flaw to hide.
- The evasion analysis can only test against the sophistication of bots you build yourselves; a truly determined real-world adversary with more resources could potentially do more — this is normal for security research and should be stated plainly as future work, not oversold as a solved problem.
- Results characterize this specific controlled setup; broader generalization claims should be made cautiously in the paper's conclusion.
