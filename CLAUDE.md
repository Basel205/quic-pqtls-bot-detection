# Project Context — Consistency-Aware Bot Detection over Next-Generation Network Protocols

This file is the authoritative context for anyone (human or AI) working on this repo. Read this before touching any code. It supersedes nothing in `Docs/` — it extends it with the newer research direction the team has since converged on.

---

## Handoff notes for Basel — read this before opening your own files

This section exists because a lot of work landed while you weren't in the loop, including in
files the Team section below lists as your ownership. Nothing here is meant to silently claim
your files — every place your code was touched is flagged explicitly, below and inline in Current
Status.

**Files that are "yours" per the Team section but were filled in or modified this phase:**
- `ml/train_baseline.py`, `ml/train_enhanced.py` — were empty (0 bytes); now thin wrappers around
  `ml/train_utils.py` (new, shared logic). Feel free to restructure if you'd built these
  differently in your head — the underlying `train_and_evaluate()` in `train_utils.py` is what
  actually matters and is easy to keep even if you change the entry points.
- `ml/ml_config.py` — had broken imports (dotted paths that can't work with this project's
  hyphenated directory names, plus a reference to a module that doesn't exist) — fixed, and later
  extended with the two ablation-arm experiment definitions.
- `ml/evasion_test.py` — was empty; built from scratch this phase (Tier-4 evasion test).
- `traffic-gen/bot_tier4_adaptive.py` — was a deliberate stub per your original plan (OpenSSL CLI
  + hand-rolled aioquic stack); **implemented differently** — reuses your `bot_tier3_sophisticated.py`
  approach (real headless Chrome) instead, since that already proved real PQ+QUIC negotiation with
  no bespoke protocol work. Rationale and full design in the Tier 4 section below — flagging this
  as a deviation from your original plan, not a silent rewrite.
- `traffic-gen/session_orchestrator.py`, `traffic-gen/tg_config.py` — extended (not rewritten) to
  support Tier 4 via an explicit `--tier bot_t4` path that never gets folded into a default full run.
- `feature-extraction/*.py` (`build_dataset.py`, `feature_schema.py`, `pq_detector.py`,
  `quic_parser.py`, `timing_extractor.py`) — several real bugs fixed (see the bug list below the
  Execution Order progress) plus the Step 3 multi-hot schema change. All still your module to own
  going forward; changes were bug fixes and one team-approved schema decision, not a redesign.

**What you should sanity-check yourself, since it's easy to want independent confirmation of your
own module's numbers:** the A/B training results and the evasion test's use of your presence
features — `ml/results/*.json` has the raw numbers, `ml/train_utils.py` has the training logic,
and everything reproduces exactly on rerun (verified this session — see the reproducibility check
in Current Status).

**Before you run anything:** `feature-extraction/dataset.parquet`, `ml/tier4_dataset.parquet`,
`ml/model_registry/*.joblib`, and `capture/pcap_store/*.pcap` are all gitignored — they exist in
this working copy but won't come through on `git pull`. Ask how to get them (or regenerate — the
main run takes a couple of hours) before assuming a script that reads them will just work.

**The one thing that actually needs your decision, not just your awareness:** the open
methodology question at the end of the "Ablation-vs-Tier4 follow-up" section below — whether to
give a future training run real exposure to Tier-4-like examples. Everything else is either done
or is a "next natural step" that doesn't need a decision, just time.

`README.md` was rewritten this session to reflect current status (it still had your original
Phase 1-3 "Next Steps" section, describing D1/D2 work that's now fully done) — worth a skim
alongside this file.

---

## Current Status (read this first — update it every session)

**Last updated:** 2026-09-12

**Execution Order progress** (see full steps below):
- ✅ **Step 1 (fix blocking bugs) — complete.** `TSHARK_INTERFACE` confirmed via live capture test (`\Device\NPF_Loopback`); `curl_cffi==0.16.0` pinned in `requirements.txt`; `client_identity_id` grouping (batches of 3-5 sessions) added to `session_manifest.csv`, `db/schema.sql`, and `session_orchestrator.py`.
- ✅ **Step 2 (20-session pilot) — complete, and fully clean.** 20/20 pcaps non-empty, **20/20 have a real captured ClientHello** (5/5 per tier — see the capture-race fix below), `client_identity_id` grouping verified correct in `session_manifest.csv`, `dataset.parquet` built with all 20 rows and every field populated with real (non-placeholder) values. Four blocking bugs, two data-quality gaps, and one capture-reliability bug found and fixed along the way (see below). The pilot was regenerated partway through this work to replace sessions caught by the capture-race bug — `session_manifest.csv` and `capture/pcap_store/` now contain only the final, clean 20 (5 human / 5 bot_t1 / 5 bot_t2 / 5 bot_t3), not the intermediate broken ones.
- ✅ **Step 3 (multi-hot decision) — resolved and implemented.** Decision: **multi-hot**, not single-hashed. Rationale (user asked for my recommendation, weighed against showing results in ~2 months): the Research Gap section's whole premise is that spatial-inconsistency scoring (Step 5) needs to know *which* attribute combination a session presented, not just an opaque digest of it — a single hash collapses exactly the detail D1/D2 depend on, and the vocabulary needed here is small and bounded, so the extra engineering cost is low relative to the payoff. Implemented and confirmed populating correctly against the same 20 pilot pcaps (no new capture run needed — pcaps don't depend on the feature schema).

**Bugs found and fixed during Step 2/3 (small diffs):**
- `db/init_db.py`: `open(schema_path, 'r')` had no explicit encoding, so Python fell back to Windows' cp1252 codec and crashed on the box-drawing characters (`═`, `─`) in `schema.sql`'s comments. Fixed: added `encoding='utf-8'`.
- `feature-extraction/pq_detector.py`: unused `from scapy.layers.tls.record import TLS` import — never referenced anywhere in the file (it does its own manual struct-based ClientHello parsing) — but importing it registers scapy's TLS dissector on port 443 as a global side effect, which then made `rdpcap()` in every extractor crash with `'readConnState' object has no attribute 'compression'` (a scapy/cryptography version mismatch, likely from the unpinned scapy install). Fixed: removed the dead import.
- `feature-extraction/build_dataset.py`: `write_to_sqlite()` only popped `session_id` before inserting into the `features` table, not `label` — but `label` lives in the `sessions` table only, so every insert failed with `table features has no column named label`. Fixed: also pop `label`. Also fixed a `→` character in a print statement that crashed with `UnicodeEncodeError` under Windows' cp1252 console encoding (same root cause as the `init_db.py` bug) — replaced with `->`.
- `feature-extraction/quic_parser.py`: `quic_transport_param_count` was a hardcoded `-1` stub (comment: "Requires CRYPTO decryption; deferred"). Implemented: derives RFC 9001 Initial secrets via `aioquic` (public-salt HKDF, no server cooperation needed), decrypts the client's Initial packet(s), reassembles the CRYPTO stream across packets if the ClientHello spans more than one (common here since the PQ key share pushes it past ~1200 bytes), and counts entries in the `quic_transport_parameters` extension (0x0039) by reusing `pq_detector.parse_clienthello` on the reassembled bytes. `aioquic==1.2.0` (already pinned in `requirements.txt`, just not installed) added to this machine's environment — installed cleanly with a prebuilt wheel. Verified: now `13` for all 10 QUIC sessions in the pilot, `-1` (correctly) for the 10 non-QUIC sessions. Known limitation, not handled: a QUIC Retry (DCID/packet-number reset) would break the reassembly — falls back to `-1` rather than mis-parsing.
- `feature-extraction/timing_extractor.py`: `inter_request_timing_cv` and `session_request_count` were computed from TCP SYN gaps, but sessions use HTTP keep-alive (0-1 new TCP connections per session) and QUIC has no TCP SYN at all — structurally always `0.0`/near-`0`. Fixed: both now derive from per-request `ts` timestamps in `target-site/logs/access.log`, matched to the session via the `X-Session-ID` header (same correlation approach `ja4h_extractor.py` already used). `record_layer_timing_p50` untouched — it was already populating correctly from pcap TLS record timing. `extract_timing_features()` signature changed: now takes `(pcap_path, session_id, access_log_path)`; `build_dataset.py`'s call site updated to match. Verified: human sessions now average CV `0.45` (most erratic) vs. bot_t2's `0.15` (most uniform) — real separation instead of a flat 0; `session_request_count` now matches actual request counts (bots: 6, matching `TARGET_PAGES`; human: 11-15, matching `HUMAN_SESSION_REQS`) instead of 0/1.
- Multi-hot implementation: `feature_schema.py` gained `SUPPORTED_GROUPS_VOCAB` (x25519, secp256r1, secp384r1, secp521r1, x25519mlkem768 + `sg_other` catch-all, GREASE excluded) and `ALPN_VOCAB` (h2, http/1.1, h3 + `alpn_other`), replacing the old `supported_groups_hash`/`alpn_hash` scalar fields with 10 multi-hot int fields on `FeatureVector`. `pq_detector.py` gained `multi_hot_supported_groups()`/`multi_hot_alpn()` helpers. `db/schema.sql`'s `features` table updated to match — **the DB file was deleted and recreated from the new schema** (`db/bot_detection.db`), so the `sessions` table rows from the Step 2 orchestrator run were lost from the DB (not from `session_manifest.csv`, which is the source of truth and is untouched); reran `build_dataset.py` against the same 20 existing pcaps to repopulate `features` + `dataset.parquet` — no new traffic-gen/capture run was needed since pcaps don't depend on the feature schema.

**Capture-reliability bug found and fixed (`capture/capture_sidecar.py`):** the `bot_t2`-all-zero observation above turned out to be a real, systematic bug — not curl_cffi-specific, and not pilot-scale noise. Root cause: `start_capture()`'s fixed `time.sleep(0.5)` after launching tshark was a race — confirmed by direct pcap inspection (every packet in a "broken" bot_t2 pcap started with `0x17`/Application Data, with not even a TCP SYN present — tshark's Npcap handle wasn't live yet when the whole handshake happened) and by cross-checking against `tests/gate1_5_tier2_verify.py`, which uses a 1.0s warmup and reliably found the ClientHello. It hit `bot_t1` too (4/5 sessions), just less consistently. Fixed in two parts: (1) `start_capture()` now blocks on tshark's own stderr "Capturing on '...'" line (confirmed empirically to be the actual readiness signal) instead of guessing with a sleep, via a daemon thread draining stderr; (2) that signal alone still wasn't sufficient — re-testing showed only the *first* session in each fast back-to-back batch succeeded, because Python's one-time module-import overhead (`import bot_tier1_naive` etc., cached after the first call) happened to provide enough incidental buffer for session 1 but not for sessions 2+. Added a `POST_READY_BUFFER_SECONDS = 0.4` sleep after the readiness signal as an empirically-justified safety margin. **Re-verified against a full 5-session bot_t1 + 5-session bot_t2 re-run: 10/10 now capture a real ClientHello** (previously 1/10 across both tiers combined). This bug would have affected up to 800 of the 1,600 Step 4 sessions (tier1 + tier2) had it gone to the full run — those sessions' classical TLS features would have been a degenerate all-zero column, which the ML model could trivially (and misleadingly) use to separate them from human/tier3 instead of learning real fingerprint differences.

- ✅ **Step 4 (full 1,600-session generation run) — complete, fully clean, zero errors.** Ran `session_orchestrator.py` with default class targets: human 500, bot_t1 400, bot_t2 400, bot_t3 300. **1600/1600 sessions succeeded, 1600/1600 pcaps non-empty, 0 tshark/curl_cffi/orchestrator errors of any kind** — the capture-race fix held up at full scale exactly as the 10-session re-test predicted. Ran `build_dataset.py` against all captured pcaps (1620 = the 1600 new + the 20 from the Step 2/3 pilot, which reused the same pcap store); excluded the 20 pilot session_ids from the final `dataset.parquet` so it matches the documented class targets exactly (the pilot was always meant as disposable pipeline-validation data, not part of the main set — pilot pcaps are still on disk, just not in the dataset). **Final `dataset.parquet`: 1600 rows × 28 columns, class balance human=500/bot_t1=400/bot_t2=400/bot_t3=300 exactly matching plan, zero NaN cells, zero duplicate session_ids.**
  - Field-completeness check (the Step 2/4 ask — "flag anything still stuck at a placeholder"): **100% ClientHello capture success across all 1600 sessions, all 4 tiers** (was the headline risk after the capture-race bug — now fully resolved at scale). Nullable QUIC/PQ fields (`pq_keyshare_data_len`, `quic_version`, `quic_transport_param_count`, `quic_conn_id_len`) are `-1` for exactly bot_t1/bot_t2 (400/400 each, correct — those tiers don't do PQ/QUIC by design) and fully populated (zero `-1`s) for bot_t3/human (300/500, correct). No fields found stuck at a placeholder that shouldn't be.
  - Sanity-check signal separation across the full dataset (not a real experiment result — A/B/D1/D2 training is Phase 4/5, still ahead — just confirms the fingerprints are real and separating sensibly): `has_pq_keyshare`/`used_http3` are a clean 0.0 for bot_t1/bot_t2 and 1.0 for bot_t3/human. `inter_request_timing_cv` ordering is human (0.42) > bot_t3 (0.29) > bot_t2 ≈ bot_t1 (0.16) — monotonic, matches the "humans are erratic, simple bots are uniform" design intent. `sg_x25519mlkem768` (the PQ multi-hot bit) is 1 for exactly bot_t3/human, 0 for bot_t1/bot_t2. `alpn_h2` is 0 for 100% of bot_t1 (matches its docstring: plain `requests`, HTTP/1.1-only) and 1 for the other three tiers.
  - **Immediate next action for Step 5 onward:** the `consistency-layer/` work described in the Execution Order can now start against a clean, validated 1,600-session `dataset.parquet`. Tier 4 (200-session evasion bot) is still a stub, deliberately deferred to Phase 5 per the plan.

**Environment notes for this machine (Windows, Python 3.14.3) — read before assuming anything is installed:**
- Npcap + Wireshark/tshark: installed and verified working (Chocolatey's `wireshark` package does NOT bundle Npcap — it had to be installed separately from npcap.com).
- Python packages needed for the Step 2/3 code path (traffic-gen + feature-extraction only — NOT ml/detection-service/dashboard, which aren't needed yet) are installed: `requests` 2.32.0, `scapy` 2.5.0, `numpy` 2.4.3, `pandas` 3.0.2, `pyarrow` 25.0.1, `playwright` 1.62.0 + Chromium, `aioquic` 1.2.0 (pinned version, installed cleanly with a prebuilt wheel — pulled in `cryptography` 50.0.0, `pylsqpack`, `pyopenssl`, `service-identity` as unpinned transitive deps). **`pandas`/`pyarrow`/`playwright` were installed unpinned** (newer than `requirements.txt`'s pins) because the pinned versions have no prebuilt wheels for Python 3.14 and would need a full C++ build toolchain to compile from source. `requirements.txt` itself was NOT changed for this — it's a local workaround, not a repo decision.
- ⚠️ **Security note, unresolved:** `requests==2.32.0` (the exact version pinned in `requirements.txt`) is a **yanked PyPI release** — pip warns it "conflicts with the CVE-2024-35195 mitigation." Should probably be re-pinned to a newer patch version; hasn't been decided yet.
- `target-site/` npm deps: installed cleanly (`npm install`, 0 vulnerabilities).
- Caddy: **installed and confirmed working** (`caddy v2.11.4`, via Chocolatey). Local CA root cert auto-installed into `Cert:\LocalMachine\Root` on first `caddy run` (confirmed via PowerShell) — explicit `caddy trust` wasn't needed since it auto-installs unless run as an unprivileged service account. Target site is up: `node server.js` on :3000, `caddy run --config target-site/Caddyfile` fronting it on :443 with HTTP/3 enabled, both currently running as background processes in this session (task IDs `b73nfwnyd` node, `b70qw6qil` caddy — restart both before running the full Step 4 dataset generation in a fresh session).
- ⚠️ curl on this machine reports `CRYPT_E_NO_REVOCATION_CHECK` against `https://localhost:443` (schannel can't OCSP-check a local self-signed CA) — this is expected/cosmetic, not a real trust failure; confirmed cert is trusted via `--ssl-no-revoke` and via the Windows cert store directly.

- ✅ **Step 5 (consistency-scoring layer, D1) — spatial scorer built, checkpoint run, awaiting decision on what's next.** New `consistency-layer/` directory, kept separate from Basel's files per convention.

**Panel feedback addressed this session: "don't only train on data we generated ourselves — use existing data too."** Researched public datasets at this project's actual layer (network/TLS/QUIC, not just generic bot-traffic logs):
  - **JA4+ Database (ja4db.com)** — real-world JA4→application/OS/library mappings, used successfully for this exact bot-detection task in a Feb 2026 ITU paper (0.998 AUC). **Turned out to be a dead end for this project**: its programmatic API (`/api/full-downloads`, `/api/exports/`) requires account signup — confirmed via direct probing (both return `401{"detail":"Authentication credentials were not provided."}`); I can't create a third-party account on the user's behalf. Not integrated. Revisit only if someone signs up and shares an API key.
  - **Pivoted to a better-fitting source**: the public artifact behind "On the Internet, Nobody Knows You're an LLM Bot: Unmasking Web Agents with Multi-Layer Fingerprinting" (arXiv:2606.30119, June 2026) — freely accessible, no auth, at `https://anonymous.4open.science/r/On_the_Internet_Nobody_Knows_You-re_an_LLM_Bot_Artifacts-C7BD/`. 1,383 real passively-captured TLS fingerprints (via tshark — same capture philosophy as this project) from 16 client types: 40 genuine `Human` rows plus 15 automated tools (Selenium, Puppeteer, Playwright, Crawl4AI×3, BrowserUse×2, Skyvern, OpenClaw, Claude for Chrome, ChatGPT Agent, curl, wget, scrapy). Includes real observations of the `0x11ec` PQ codepoint this project is built around, from actual Chrome 144. A trimmed copy (10 of ~140 columns — TLS/ALPN fields only) lives at `consistency-layer/external-data/llm_agent_study_tls_fingerprints.csv`; full provenance/caveats in that directory's `README.md`.

**Step 5 implementation:**
  - `consistency-layer/external_reference.py` — normalizes the external CSV into this project's own multi-hot vocabulary (`SUPPORTED_GROUPS_VOCAB`/`ALPN_VOCAB` from `feature_schema.py`). Documented, deliberate granularity mismatch: external ALPN is the *negotiated* protocol (one value), ours is the *offered* list (can be several) — treated as "this protocol was present," never "this was the complete offered set."
  - `consistency-layer/expected_combinations.py` — builds the Step 5 expected-combination table from `(tls_version, has_pq_keyshare, used_http3, supported_groups multi-hot, alpn multi-hot)`, combining our own 500 lab human sessions **with** the external artifact's 40 real Human rows (tagged `source=lab` vs `source=external_llm_agent_study` in the output, so the mix stays auditable) — this is the concrete answer to the panel's ask, not just a validation footnote. `cipher_suite_order_hash` (named in this file's original Step 5 spec) is deliberately excluded from the cross-source key — see the module docstring for why, and the empirical confirmation below for why it wouldn't have added separation power anyway.
  - `consistency-layer/spatial_score.py` — the D1 scoring function: `-log2(probability)` of a session's combination under the expected-combination table (0 = fully expected, ~9.08 bits = never seen among any human-labeled session, lab or external). Per-session scores for all 1,600 sessions saved to `consistency-layer/d1_spatial_scores.csv`.

**Found and fixed a real bug while validating this** (not hypothetical — it directly affected the expected-combination table's correctness): `alpn_h3` was `0` for *every* session in `dataset.parquet`, even the 800 QUIC ones. Root cause: `pq_detector.py`'s multi-hot ALPN only ever parsed the TCP-layer ClientHello (a QUIC session also opens a separate TCP fallback connection with its own ALPN offer), so the QUIC connection's own `h3` ALPN offer was never seen. Fixed: `quic_parser.py` now also returns the QUIC ClientHello's ALPN (refactored `_extract_transport_param_count` into a shared `_reassemble_quic_clienthello` helper so both use one decrypt); `pq_detector.py` now also returns the raw TCP-layer ALPN list (`tcp_alpn`, not just its own multi-hot encoding); `build_dataset.py` merges both lists before computing the final `alpn_*` fields. Re-ran `build_dataset.py` against all 1,620 pcaps (few minutes, no new capture needed) — verified `alpn_h3` now exactly matches `used_http3` for all 800 QUIC sessions (was 0/800, now 800/800). `dataset.parquet` re-trimmed back to the clean 1,600 (pilot sessions excluded again).

**The Step 5 checkpoint result (human vs. bot_t2/bot_t3, as this file's Step 5 spec requires before building further) — and it's an honest, meaningful one, not a clean win across the board:**
```
label    mean score   separates from human?
bot_t1   9.08 bits     yes — combination never seen among any human-labeled session
bot_t2   9.08 bits     yes — same as bot_t1 (no PQ, no QUIC — completely different combination)
bot_t3   0.111 bits    NO — scores identically to human
human    0.111 bits    (reference)
```
Confirmed this isn't a scoring bug by checking `cipher_suite_order_hash`/`extension_order_hash` directly: bot_t3 draws from the *exact same 16-value set* of cipher orderings as human (full overlap), and `extension_order_hash` is unique per-session for *both* human and bot_t3 (500/500 and 300/300 unique — almost certainly Chrome's GREASE-randomized extension order, faithfully replicated by bot_t3). Adding either field to the combination key would not separate bot_t3 from human — bot_t3 is, by design, that good a mimic at this layer. **This is expected, not a failure**: it's the project's own central hypothesis playing out empirically — presence/spatial-only checks catch unsophisticated bots (t1/t2) but not a bot deliberately built to replicate real protocol-level randomization (t3), which is exactly why D2 (temporal — does a claimed-repeat client's fingerprint drift across sessions) exists as "the fuller hypothesis test" per this file's Proposed Solution section. D1 alone is confirmed to be "the safer fallback result," not the whole story, exactly as already documented.

**Decision made (user deferred to recommendation): build D2 now, don't chase finer spatial features.** The cipher/extension-hash check above already showed that path is a dead end — proceeded straight to D2.

- ✅ **D2 temporal score — built, and it surfaced an important, honest limitation.** `consistency-layer/temporal_score.py`: for each session, mean fraction of a 16-field "should stay stable across repeat visits" set (`TEMPORAL_FIELDS` — tls_version, has_pq_keyshare, used_http3, ja4_fingerprint_hash, quic_version, quic_transport_param_count, all 10 multi-hot sg_*/alpn_* fields) that differ from every other session sharing the same `client_identity_id`. Deliberately excludes `cipher_suite_order_hash`/`extension_order_hash` — real browsers GREASE-randomize both per-connection (confirmed by the Step 5 checkpoint finding above), so treating them as "should be stable" would flag genuine same-device repeat visits as inconsistent just as often as an actual bot. **Result: the score is exactly `0.0` for all 1,600 sessions, every tier, no exceptions** — spot-checked directly (see a 4-session `client_identity_id` group's raw field values in this session's transcript if needed): every session in every group is byte-identical to its siblings on every temporal field. This is real, not a bug: `bot_tier1_naive.py`/`bot_tier2_evasive.py`/`bot_tier3_sophisticated.py`/`human_traffic.py` are all deterministic — same tool/library/profile every single call, no proxy rotation or version drift — so there is currently no fingerprint drift anywhere in the dataset for D2 to detect. **D2 cannot be meaningfully evaluated until Tier 4 (Phase 5's adaptive evasion bot) exists** — an adaptive bot that changes tactics between visits is precisely what would produce real temporal drift. Per-session scores saved to `consistency-layer/d2_temporal_scores.csv` for completeness/pipeline-readiness, not as a claimed finding.

- ✅ **ML training pipeline — built from scratch (it did not previously exist) and all four experiments (A/B/D1/D2) run successfully.** Found `ml/train_baseline.py`, `train_enhanced.py`, `evaluate.py`, `evasion_test.py`, `feature_importance.py` all completely empty (0 bytes), and `ml_config.py` (the only non-empty file) had broken imports — dotted package-style imports (`from feature_extraction.feature_schema import ...`) that can't work with this project's hyphenated directory names, and referenced a nonexistent `traffic_gen.config` module (real file is `tg_config.py`). Fixed `ml_config.py` to use the established `_paths.py` bootstrap pattern; also removed `use_label_encoder` from `XGBOOST_PARAMS` (removed from the XGBoost API in versions ≥1.6; pinned version is 2.1.0, would have raised `TypeError`). Installed `xgboost==2.1.0` (pinned version, clean prebuilt-wheel install) — `catboost`/`shap`/`mlflow` still not installed, not needed yet (CatBoost comparison and SHAP are later work; skipped MLflow in favor of the simpler JSON-results-file approach below, `db/schema.sql`'s `model_runs` table already exists as the documented lightweight alternative if needed later).
  - `feature_schema.py` gained `EXPERIMENT_D1_FEATURES` (= B + `spatial_inconsistency_score`) and `EXPERIMENT_D2_FEATURES` (= D1 + `temporal_inconsistency_score`) — these engineered scores aren't in `dataset.parquet` itself, joined in at load time from the consistency-layer CSVs.
  - `ml/train_utils.py` (new) — shared load/split/train/evaluate logic: stratified train(70%)/val(15%)/test(15%) split (`tg_config`'s `TEST_SIZE`/`VAL_SIZE`), XGBoost classifier (`ml_config.XGBOOST_PARAMS`), reports accuracy/macro-F1/multi-class ROC-AUC (one-vs-rest), saves model to `ml/model_registry/{experiment}.joblib` and metrics to `ml/results/{experiment}.json`.
  - `ml/train_baseline.py` (A) and `ml/train_enhanced.py` (B) are now thin wrappers around `train_utils.py` — kept as the two dedicated entry points since those filenames are Basel's designated ownership per the Team section below, even though I (this session) filled them in; flagging that clearly rather than silently claiming Basel's files as untouched.
  - `consistency-layer/train_d1_d2.py` (new) — trains D1 and D2, kept in `consistency-layer/` rather than `ml/` since D1/D2 are this module's ownership, not Basel's. Recomputes both score CSVs from the current `dataset.parquet` before training so they can never go stale relative to the model being trained.

**Results (1600 sessions: train 1120 / val 240 / test 240, stratified):**
```
Experiment              Accuracy   Macro-F1   ROC-AUC(ovr)   vs. B
A_baseline              0.800      0.775      0.925          (classical TLS/JA4 only)
B_enhanced              0.9958     0.9956     1.000           —
D1_spatial              0.9958     0.9956     1.000          identical to B, bit-for-bit
D2_spatial_temporal     0.9958     0.9956     1.000          identical to B, bit-for-bit
```
B's *entire* error is one misclassification out of 240 test sessions — confirmed via confusion matrix: 1 real `human` session predicted as `bot_t3`, everything else (including all of bot_t1 and bot_t2) perfect. **This is exactly the confusion the Step 5 checkpoint predicted D1 can't resolve** (bot_t3 and human score identically on the spatial dimension) — and empirically, adding the spatial score changes literally nothing about the model's predictions (same accuracy to the decimal, same model behavior). D2 is identical to D1 for the reason above (temporal score has zero variance to learn from). This is a clean, internally-consistent story end to end: A → B shows presence-based PQ/QUIC/timing signals are highly discriminative (the project's baseline contribution); B's one residual error is precisely the case D1 is theoretically blind to; D2 is honestly not yet testable. **The natural next real result for this project is Tier 4 + D2**, not further tuning of A/B/D1 on this dataset.

**Immediate next action (superseded by the entry below — kept for history):** ~~Tier 4 (Phase 5's adaptive evasion bot) is the load-bearing next step...~~

- ✅ **Tier 4 (adaptive evasion bot) — implemented, 200/200 sessions generated clean, evasion test run and thoroughly investigated (including a follow-up ablation study), Phase-gating rule's required evasion-resistance test now satisfied.** `traffic-gen/bot_tier4_adaptive.py` (was a stub) and `ml/evasion_test.py` (was empty, 0 bytes) both built this session. See the two sections directly below for the full result and its mechanism.

**Design decision (documented here, same convention as Step 3's multi-hot decision) — deviates from the original stub's plan:** the stub called for a hand-rolled OpenSSL 3.5 CLI client + a forced aioquic stack. Superseded because `bot_tier3_sophisticated.py` already proved a real headless Chromium engine (via Playwright) genuinely negotiates the PQ key share and QUIC/HTTP3 with zero bespoke protocol work — building a second, hand-rolled TLS/QUIC stack would buy no extra realism and works against this project's "reuse, don't rebuild" principle. Tier 4 is built the same way as Tier 3, plus two additions targeting the two gaps the ML results exposed:
1. **Human-mimicking timing and session length** (`HUMAN_DELAY_MEAN/STD`, `HUMAN_SESSION_REQS`) instead of Tier 3's fast/uniform bot timing — closes B's one remaining tell (the single bot_t3→human confusion-matrix error was timing-driven).
2. **Split backend-profile model within each `client_identity_id` group**: each session independently gets `TIER4_DEGRADED_PROFILE_PROB = 0.3` chance of the "degraded" profile (Chromium launched with `--disable-quic`, simulating a bot-farm worker/exit-node whose path doesn't proxy QUIC's UDP) vs. "full" (default args, protocol-indistinguishable from human). This is what gives D1 a realistic inconsistent combination to catch (100% of this project's human sessions have PQ+QUIC, so a "degraded" session's combination — PQ present, QUIC absent — has never been observed among human-labeled sessions) and gives D2 real cross-session drift whenever a `client_identity_id` group lands on a mix of both profiles, instead of D2's current flat 0.0. Whether a given identity-group happens to land all-"full" (fully evading both) or mixed (caught by one or both) is left to chance, matching the original stub's "partial degradation is an expected and valid research finding."

`session_orchestrator.py` changes: `TIER_MAP` (used by a bare full-run invocation) still excludes bot_t4 on purpose — Tier 4 is generated only via the explicit `--tier bot_t4` path (new `ALL_TIER_MAP` for that lookup), so it can never accidentally get folded into a re-run of the main 1,600. `run_session()`/`run_tier()` gained a `degraded: bool` parameter, assigned per-session inside a `client_identity_id` group via `TIER4_DEGRADED_PROFILE_PROB` (new constant in `tg_config.py`).

**A real, unrelated environment bug found and fixed while pilot-testing this:** an 8-session pilot's `used_http3` came back `0/8` even for "full"-profile sessions — every session (regardless of profile) showed zero UDP/QUIC traffic in the pcap at all. Root cause, confirmed by direct inspection: Caddy (freshly restarted this session after an 18-day idle gap, per this file's own environment notes) was serving a **TLS certificate that had already expired** (`notAfter=Aug 19 2026`, today is Sep 7) — its automatic leaf-cert renewal was stuck in a broken retry loop (`open ...\localhost.key: The system cannot find the file specified`) left over from an earlier interrupted cleanup of the old expired cert's files. `curl --insecure` and Chromium's automation `ignore_https_errors` both happily proceed past an invalid cert for normal HTTP(S) navigation, but Chromium's QUIC/Alt-Svc upgrade path does its own independent certificate validation that automation flags don't override — so it silently never attempts QUIC at all, degrading every session (any tier, not just bot_t4) to TCP-only without any visible error. Fixed by stopping Caddy, deleting the stale `certificates/local/localhost/localhost.json` metadata left behind after the .crt/.key were already removed, and restarting — Caddy then obtained a fresh valid leaf cert immediately ("certificate obtained successfully"). Verified via a manual 20-request Playwright diagnostic + direct pcap inspection: 0 UDP/QUIC frames before the fix, real `udp`/`quic` frames after. **This means the target-site services must be freshly verified (not just "is a process running") after any idle gap, not just restarted** — a running-but-serving-an-expired-cert Caddy looks identical to a healthy one from a plain `curl` check or an HTTP 200. The 8 pilot sessions captured before this fix were discarded (pcaps + manifest + DB rows deleted) and regenerated cleanly after.

Pilot (8 sessions, post-fix) confirmed the design works exactly as intended: PQ present in 100% of sessions regardless of profile (`has_pq_keyshare=1`); QUIC fields cleanly toggle with the profile (full: `used_http3=1, quic_version=1, quic_transport_param_count=13, alpn_h3=1`; degraded: all off); timing CV ranged 0.18–0.61 (vs. Tier 3's old ~0.15 uniform bot timing, now overlapping human's ~0.45 average); one identity group landed all-degraded (3/3), one landed genuinely mixed (2 full + 1 degraded — real D2 drift material), one landed all-full.

`ml/evasion_test.py` (new): loads the four already-trained models (A/B/D1/D2) from `ml/model_registry/`, extracts bot_t4 features directly from pcaps into a separate `ml/tier4_dataset.parquet` (never touches or rebuilds the main `dataset.parquet` — the 1,600-session A/B/D1/D2 training set stays exactly as-is), joins in D1's spatial score (against the existing human-derived expected-combination table, unaffected by bot_t4) and D2's temporal score (drift within each bot_t4 session's own `client_identity_id` group — bot_t4's groups never share an identity with any other tier, so this only ever compares a bot_t4 session against its bot_t4 siblings), and reports each model's evasion rate (% of bot_t4 sessions misclassified as "human"). Smoke-tested end-to-end against the first 14 captured sessions — pipeline runs clean, no errors; **not yet a real result** — 14 sessions is too small and skewed toward the pre-full-run pilot batch to draw any conclusion from, full 200-session numbers are the ones that matter.

**Full 200-session run: complete, clean.** 192/192 remaining sessions succeeded (192/192 pcaps non-empty, 0 errors) on top of the 8-session pilot = 200/200 total, 200 unique session_ids, 53 distinct client_identity_id groups. `used_http3` split 129 full-profile (1) / 71 degraded-profile (0) — close to the configured 70/30 target, as expected from independent per-session random assignment.

## Evasion test result (the required primary outcome per the Phase-gating rule) — a real, honest, non-obvious finding

```
Model                  Evasion rate   Predictions
A_baseline             73.5%          147 human, 53 bot_t3
B_enhanced             97.0%          194 human, 6 bot_t3
D1_spatial             97.0%          194 human, 6 bot_t3   <- byte-for-byte identical to B
D2_spatial_temporal    97.0%          194 human, 6 bot_t3   <- byte-for-byte identical to B
```

**D1/D2 provide zero additional evasion resistance over B against Tier 4 — same 194/200 sessions misclassified as human, same 6 caught, in both cases.** This directly cuts against the project's central hypothesis as currently instrumented, so before accepting it, checked whether the consistency scores themselves are broken:

- **They are not.** Recomputed both scores directly against the 200 tier4 sessions: `spatial_inconsistency_score` is exactly `9.079` bits (the same "never seen among humans" ceiling bot_t1/bot_t2 score) for all 71 degraded-profile sessions and exactly `0.111` bits (matching human) for all 129 full-profile sessions — a perfect, correct split. `temporal_inconsistency_score` is nonzero for 165/200 sessions (mean 0.121, up to 0.25) — real cross-session drift, correctly detected, finally giving D2 something to work with after Step 5's flat-0.0 finding.
- **The actual cause: both trained models assign `spatial_inconsistency_score` and `temporal_inconsistency_score` exactly `0.0` feature importance** (confirmed directly against `D1_spatial.joblib`/`D2_spatial_temporal.joblib`'s `feature_importances_`) — the models never learned to use either score at all, which is why their predictions are identical to B's down to the session. Mechanism: on the 1,600-session lab training distribution, `spatial_inconsistency_score` is a **deterministic, redundant function of raw features already in the model** — every training session with `has_pq_keyshare=0` (bot_t1/t2) also has `used_http3=0` and scores exactly 9.08 bits, and every session with `has_pq_keyshare=1` (bot_t3/human) also has `used_http3=1` and scores exactly 0.111 bits. Gradient boosting had zero incentive to ever split on the derived score when the raw fields it's computed from already separate every training example perfectly. Tier 4's degraded sessions land in a **region of feature space that never existed in training**: `has_pq_keyshare=1` (Chrome still offers the PQ key share — `--disable-quic` only kills the QUIC transport, not TLS-level PQ) **combined with** `used_http3=0`. The model, never having learned to weight `used_http3`/`alpn_h3` heavily on their own (importances 0.035 and lower — `has_pq_keyshare`/`sg_x25519mlkem768` dominate at 0.080/0.072), defaults toward "human" in this novel region: PQ presence outweighs QUIC absence in the learned boundary, and the one feature that would have flagged the inconsistency directly (the spatial score) was never given any weight to begin with.

**This is a more precise and more useful finding than "consistency scoring doesn't help":** the signal is real, correctly computed, and — per the direct score comparison above — maximally informative on exactly the sessions that matter. It's invisible to the *current* models purely because it's collinear with other features on the training distribution they were fit to, so the trees route around it. This is precisely what the Ablation Study section's **Spatial-consistency-only** and **Full-consistency-only** arms (Classical + score, deliberately *without* the raw PQ/QUIC/timing fields the score is currently redundant with) are positioned to test — those arms would force a model to actually rely on the score, since the shortcut features it currently uses instead wouldn't be available. **Recommended next step: run those two ablation arms and evaluate them against Tier 4 too** (not just the classical baseline, which is all the Ablation Study section originally specified) — this is the natural, direct follow-up to resolve whether the consistency signal has real evasion-resistance value once the model is actually forced to use it, and it's a bounded, cheap experiment (retrain 2 more XGBoost models on already-computed features, no new data generation). Flagging this as a scope extension of the Ablation Study section rather than assuming it silently — the section as written only speced ablation-vs-classical-baseline, not ablation-vs-Tier4.

Artifacts from this test: `ml/tier4_dataset.parquet` (200 bot_t4 sessions' raw features, extracted directly from pcaps — `dataset.parquet` itself, the 1,600-session A/B/D1/D2 training set, was never touched), `ml/results/evasion_test.json`.

## Ablation-vs-Tier4 follow-up (run same session, user approved) — deepens the finding, doesn't reverse it

User approved running the two Ablation Study arms the finding above raised (`feature_schema.py` gained `EXPERIMENT_SPATIAL_ONLY_FEATURES`/`EXPERIMENT_FULL_CONSISTENCY_FEATURES` = `CLASSICAL_FEATURES` + score(s), deliberately excluding `NEW_PROTOCOL_FEATURES`/`BEHAVIORAL_FEATURES`; `ml_config.py` registers them as `Ablation_spatial_only`/`Ablation_full_consistency`; both trained via the existing `train_utils.py`, no new infra needed) and re-ran the evasion test against all six models:

```
Model                       Evasion rate   Predictions
A_baseline                  73.5%          147 human, 53 bot_t3
B_enhanced                  97.0%          194 human, 6 bot_t3
D1_spatial                  97.0%          194 human, 6 bot_t3
D2_spatial_temporal         97.0%          194 human, 6 bot_t3
Ablation_spatial_only       75.5%          151 human, 49 bot_t3
Ablation_full_consistency   74.5%          149 human, 51 bot_t3
```

In-distribution (the normal held-out test split from the 1,600-session set), both ablation arms score right around A_baseline (accuracy 0.792/0.800 vs. A's 0.800) — expected, since bot_t3-vs-human confusion is the same known ceiling regardless.

**With the redundant raw fields removed, `spatial_inconsistency_score` does get real feature importance this time** (0.157 in `Ablation_spatial_only`, 0.088 in `Ablation_full_consistency` — confirmed directly via `feature_importances_`, unlike D1/D2's flat 0.0) — so the earlier hypothesis (the model ignores the score purely because it's collinear with `has_pq_keyshare`/`used_http3`) is partially right. **But the ablation arms still don't beat B/D1/D2, and don't meaningfully beat A_baseline either** (75.5%/74.5% vs. A's 73.5% — within noise, and on the degraded-profile subset specifically, `Ablation_spatial_only` actually catches *fewer* sessions than plain A_baseline: 16/71 vs. 20/71). Dug into why, since this ran counter to the hypothesis:

- Checked whether Classical features (`cipher_suite_count`, `extension_count`) themselves shift with the QUIC toggle, as a possible confound — **they don't**: both are exactly constant (16/18) across all 200 bot_t4 sessions regardless of profile. So A_baseline's ~25-28% catch rate on both full *and* degraded sessions equally isn't QUIC-toggle-driven at all — it's just A_baseline's general, pre-existing bot_t3-vs-human classical-fingerprint noise (A_baseline's overall accuracy is only 0.800, far noisier than B's 0.9958), bleeding over into Tier 4 with no relation to the profile split.
- Checked the training distribution directly: `bot_t2`'s classical fingerprint (`cipher_suite_count=16, extension_count=18`) is **byte-identical to `bot_t3`/`human`'s** — only `bot_t1` looks classically different (18/12). So among the two training-set tiers that share `spatial_inconsistency_score=9.08`, one (`bot_t2`) already looks exactly like real Chrome on every classical field. **No training example combines a genuinely Chrome-realistic classical/protocol fingerprint with a spatially-inconsistent score** — `bot_t2` has *no* PQ/QUIC signal at all (not just QUIC missing, PQ missing too), so the model has literally never seen "real Chrome fingerprint, but missing just QUIC while still offering PQ" — exactly Tier 4's degraded-profile combination — in any form, on any feature set. The tree's "high spatial score" splits, learned from `bot_t1`/`bot_t2`, stay entangled with those tiers' other differences from Chrome; they don't isolate into a standalone, generalizable "spatial inconsistency" rule that transfers to a bot that's realistic everywhere except one dimension.

**Refined conclusion:** this is not primarily a feature-selection problem (though that redundancy is real and confirmed) — it's a **training-data coverage gap**. No amount of choosing which features to expose the model to fixes a decision boundary that was never asked to draw a line through the region Tier 4 occupies. The models correctly compute inconsistency (proven at the score level, independent of any classifier) but were never trained on an example that needed it to generalize. The natural, methodologically honest fix is **not** more feature engineering on the current 1,600-session set — it's giving a future training run actual exposure to "otherwise-consistent, one-dimension-inconsistent" examples (e.g., a proper train/held-out split *within* Tier 4 itself, training on some sessions and evasion-testing on others, rather than treating all of Tier 4 as pure held-out data as this test did). **Flagging this as a real scope/methodology question for the team rather than deciding it unilaterally**: folding some Tier 4 data into training changes what "evasion test" means for the paper (train/test contamination has to be handled carefully — e.g. split by `client_identity_id` group, never split a group across train/test) — worth discussing before implementing, not a small follow-up to just do.

Artifacts: `ml/model_registry/Ablation_spatial_only.joblib`, `ml/model_registry/Ablation_full_consistency.joblib`, `ml/results/Ablation_spatial_only.json`, `ml/results/Ablation_full_consistency.json`, `ml/results/evasion_test.json` (updated, now 6 models).

**Immediate next action:** this is a natural checkpoint — the Phase-gating rule's required evasion-resistance test is now complete and thoroughly investigated (not just run once and reported). Recommend discussing the train/held-out-split-within-Tier-4 question above with the team before proceeding, since it changes methodology rather than just adding another experiment arm.

- ✅ **Pre-push verification pass (2026-09-12)** — user asked to confirm everything is correct and complete before pushing to GitHub for Basel to review. Findings:
  - Every `.py` file in the repo compiles clean (`py_compile` over the whole tree). Every file this document references exists on disk at the expected size — checked all of them explicitly, not sampled.
  - **Reproducibility confirmed, not assumed**: reran `train_utils.py D1_spatial` and `ml/evasion_test.py` from scratch — results matched the documented numbers bit-for-bit (0.9958 accuracy; 73.5/97.0/97.0/97.0/75.5/74.5% evasion rates across all 6 models). The pipeline isn't order- or state-dependent in any way that broke on a clean rerun.
  - `dataset.parquet` re-verified directly: 1,600 rows, 28 columns, zero NaNs, zero duplicate `session_id`s, exact class balance. All 6 `.joblib` models load and report the expected feature counts (16/26/27/28/17/18, matching each experiment's defined feature list).
  - No secrets, API keys, tokens, or credential files anywhere in the tree (explicitly scanned).
  - `.gitignore` already correctly excludes the heavy/regeneratable artifacts (`*.joblib`, `*.parquet`, pcaps, the SQLite DB, `node_modules`, logs) — a dry-run `git add -A` stages exactly 37 files, all small text/code/CSV/JSON, nothing that would bloat the push.
  - **Two things fixed as a result**: `README.md` (was Basel's stale Phase 1-3 handoff doc, whose "Next Steps" section described the D1/D2 consistency work as still-to-do when it's now fully done and evaluated — rewritten with a current status section, the external-dataset answer below, an updated setup guide including the Caddy-expired-cert gotcha, and accurate next steps) and this file (added the "Handoff notes for Basel" section above).
  - **One pre-existing, non-blocking git-hygiene note surfaced**: `CLAUDE.md` was showing as both a staged "new file" (an old partial version, staged at some earlier point) and "modified" (unstaged, current content) in `git status` — not a data-loss risk, but `git add -A` (not a commit of only what's currently staged) is needed before committing so the full current version actually goes in. Also noted: `traffic-gen/session_manifest.csv`'s `pcap_path` column has a local absolute Windows path baked in (harmless — no code reads that column, it's informational only) — cosmetic, not fixed, flagged for awareness.
  - **Confirmed the external-dataset integration is real and working, not just documented**: reran `consistency-layer/expected_combinations.py` fresh — output shows 540 total human-labeled sessions (500 `lab` + 40 `external_llm_agent_study`) feeding the expected-combination table, exactly as this document's Step 5 section describes. This was in response to the user specifically asking to re-verify "did we use an existing dataset" before the push — yes, confirmed end-to-end.

---

## Team

- **Basel**: built the original infrastructure and the presence-based detection approach (Phases 0-3 done, per `Docs/handoff_report.md`). Owns target-site, traffic-gen, feature-extraction, and will own Phase 4/5 (baseline + presence-enhanced ML training, Tier-4 evasion bot).
- **[You]**: building the new consistency-scoring layer described below (the team's core novel research contribution). Owns the new consistency module, Experiments D1/D2, and the evasion comparison between presence-only and consistency-augmented detection.
- Shared: Phase 6 (live proxy + dashboard), paper draft.

---

## Research Gap (Problem Statement)

**Central hypothesis of this project:** consistency-based bot detection — checking whether a connection's protocol attributes actually belong together, not just whether individual "new" signals are present — generalizes from the browser/JavaScript fingerprint layer to the network-protocol layer, and holds its advantage better than presence-only detection as bots catch up on individual signals.

Bot-detection research currently splits across two disconnected fronts:

1. **Consistency-based fingerprint detection.** FP-Inconsistent (ACM IMC 2025, UC Davis) found that evasive bots trying to fake individual browser fingerprint attributes tend to produce *combinations* that don't occur on real devices — spatial inconsistency (attributes that don't belong together) and temporal inconsistency (an attribute drifting across requests claiming to be the same device). Their consistency-checking cut evasion rates ~45-48% while keeping 96.84%+ true-negative rate on real users. This method works **only at the browser/JavaScript fingerprint layer** (screen size, navigator properties, canvas hashes) — to our knowledge, it has never been applied at the network-protocol layer.

2. **Presence-based protocol signals — the motivating baseline, not the headline.** Post-quantum TLS key exchange (X25519MLKEM768, codepoint `0x11EC`) and QUIC/HTTP-3 adoption since 2024 give real browsers signals most bot tooling hasn't caught up to yet. To our knowledge, no published academic study evaluates this as a bot-detection feature, and it's a real, defensible result on its own — this is Basel's original contribution, Experiments A/B. But presence-based detection has a structural weakness: it only works *because* bot tooling hasn't added PQ/QUIC support yet. The day that changes, presence-only detection degrades — a signal, once copied, stops discriminating. This fragility is exactly why this project exists: consistency-based detection should get *harder* to evade the more protocol layers a bot tries to spoof at once, since each added layer is another chance to be internally inconsistent, whereas presence-based detection gets easier to evade the moment any one signal is copied.

**The gap this project fills:** to our knowledge, nobody has tested whether consistency-based detection generalizes from the JS/browser layer to the network-protocol layer (TLS version, cipher suite, PQ key-share presence, HTTP version, QUIC transport parameters). Basel's presence-based signals (A/B) establish the baseline this project needs to show consistency-augmented detection (D1/D2) beats — both in raw accuracy and, more importantly, in how well the advantage survives an adaptive attacker.

**Plain-language version:** Basel's approach checks "does this connection have the new signals a real browser would have?" one at a time — useful today, but it stops working the moment bot tooling adds those signals too. This project's core claim is: "do all of this connection's protocol-level attributes actually belong together, the way they would on a real device?" — borrowing a method proven at the browser layer and applying it, to our knowledge for the first time, to network-protocol handshake data. That consistency check should stay hard to fake even after presence-only detection stops working.

---

## Scope

**In scope:**
- Reuse Basel's existing lab environment (Caddy + QUIC + PQ-TLS target site, session orchestrator, 4-tier bot traffic generation, JA4/JA4H extraction) as the shared data layer.
- Extend the feature schema with an **expected-combination layer**: derived from real human sessions, which (TLS version, cipher order, PQ presence, ALPN, QUIC version, transport parameters) combinations actually co-occur in practice.
- Build a **consistency-scoring module**: spatial checks (does this session's attribute combination match observed valid combinations) + temporal checks (does a claimed-same-client session drift across repeated connections).
- New experiment arms — the project's central empirical claim: **Experiment D1 (spatial consistency only)** and **Experiment D2 (spatial + temporal consistency)**, both compared against Basel's Experiment A (baseline) and B (presence-enhanced).
- Bounded ablation study isolating individual feature groups (PQ, QUIC, timing, spatial-consistency) — see Ablation Study section below.
- Evasion test — a required primary outcome, not optional: does D1/D2 hold its advantage against an adaptive Tier-4 bot better than B does.
- Same live-proxy + dashboard demo (Phase 6), scoring engine extended to the two-layer model.

**Out of scope:**
- Testing against real commercial anti-bot systems (no access, not needed for the core contribution).
- Large-scale real internet traffic collection — lab-generated data is a standard, defensible limitation at this project's scope.
- Exhaustive browser/OS/network-stack coverage — a representative sample is sufficient.

---

## Proposed Solution

The central claim to prove: consistency-augmented detection (D1/D2) beats presence-only detection (A/B), and holds its advantage better under evasion pressure. Everything below is in service of that comparison — A and B exist to establish the baseline this project needs to beat, not as the main event.

1. **Reuse, don't rebuild** Basel's target site, traffic generators, capture pipeline, and JA4 extraction — this infrastructure is the shared foundation, not something to duplicate or refactor away.
2. From captured human-traffic sessions, build **expected-combination tables** — the valid, observed joint distribution of protocol attributes for real browser/OS/network-stack pairs.
3. For every session, compute:
   - **Spatial inconsistency score**: how many attribute-pairs deviate from the expected joint distribution. Feeds Experiment D1.
   - **Temporal inconsistency score**: how much a session's attributes drift across repeated connections claiming to be the same client. Feeds Experiment D2 (adds to D1's spatial score).
4. Feed both scores into the ML pipeline as engineered features, alongside Basel's presence-based features (`has_pq_keyshare`, `used_http3`, etc.) trained separately as the A/B baselines to beat.
5. Train Experiments D1 and D2 and compare against A, B, and the bounded ablation arms on: accuracy, macro-F1, ROC-AUC, and — as a required primary outcome, not one that can be cut — evasion-resistance against the adaptive Tier-4 bot.

**Experiment table:**

| Experiment | Feature Set | Owner |
|---|---|---|
| A — Baseline | JA4 + classical TLS only | Basel |
| B — Presence-enhanced | + PQ + QUIC + timing | Basel |
| D1 — Consistency-augmented (spatial) | B + spatial inconsistency score | New (this contribution) — safer fallback result |
| D2 — Consistency-augmented (spatial + temporal) | D1 + temporal inconsistency score | New (this contribution) — full hypothesis |

**D1 is the safer fallback result.** If the temporal/client-identity-linkage data turns out too thin or noisy to support D2 (see Critical Dependency below), D1 alone — spatial consistency only — should still stand as a complete, publishable finding on its own. D2 is the fuller test of the central hypothesis and is reported alongside D1, not instead of it.

---

## Ablation Study

Beyond the A/B/D1/D2 comparison, run a bounded ablation (5 arms, capped at 6) that isolates one feature group at a time against the classical baseline, to determine which signal is actually doing the work rather than assuming it from the combined result:

| Arm | Feature Set | Isolates |
|---|---|---|
| PQ-only | Classical + `has_pq_keyshare`, `pq_keyshare_data_len` | PQ presence signal alone |
| QUIC-only | Classical + `used_http3`, `quic_version`, QUIC transport fields | QUIC presence signal alone |
| Timing-only | Classical + `inter_request_timing_cv`, `record_layer_timing_p50`, etc. | Behavioral timing signal alone |
| Spatial-consistency-only | Classical + spatial inconsistency score (no PQ/QUIC/timing) | Whether consistency alone, without any presence features, carries signal — a direct test of the central hypothesis |
| Full-consistency-only | Classical + spatial + temporal inconsistency scores (no PQ/QUIC/timing) | Same, with temporal added — the most direct evidence for or against the central hypothesis |

Ties directly into the SHAP feature-importance plan already in `MASTER_Implementation_Plan.md` §7: run SHAP on the D2 model to see which individual features drive predictions, then use these ablation arms to confirm at the group level whether SHAP's top features are load-bearing or just correlated noise. Report both together — SHAP shows the "what," the ablation confirms the "how much."

---

## Critical Dependency to Check Before Building the Consistency Layer

The temporal-consistency check requires **multiple connections from the same claimed client identity over time** — not just independent one-shot sessions. Before extending `feature_schema.py` or `build_dataset.py`, confirm whether `session_orchestrator.py` and `session_manifest.csv` currently support grouping sessions by claimed client identity across repeated connections. If they don't, this is a design change needed *before* the large-scale dataset generation run, not after — regenerating the 1,600-session main dataset (human/tier1/tier2/tier3; tier4 is generated separately, see below) after the fact would waste the run.

---

## Key Locked Technical Facts (inherited from Basel's docs — do not deviate without discussion)

- PQ key exchange group codepoint: **`0x11EC`** (X25519MLKEM768, IANA-registered). Do NOT use `0x6399` (retired draft codepoint, will not appear in current browser traffic).
- PQ key share payload length: ~1216 bytes (confirm empirically against your own capture, don't hardcode blindly).
- Current feature schema: 19 fields, defined in `feature-extraction/feature_schema.py` — read this file directly rather than assuming the field list, since it may have evolved since the original planning docs.
- Never use as features: User-Agent, IP, geo-data, cookies, payload content — trivially spoofable or privacy-sensitive.
- Session counts: the main dataset used to train/evaluate A/B/D1/D2 is **1,600 sessions** (human: 500, tier1: 400, tier2: 400, tier3: 300). **Tier 4 (200 sessions) is separate** — generated in Phase 5 as the evasion test against D1/D2, not part of the 1,600 and not part of the main training/eval split.

---

## Execution Order — Follow This Sequence, Do Not Skip Ahead

Do not batch these steps. Complete each one, report results, and wait for confirmation before starting the next.

**Step 1 — Fix blocking bugs (small diffs, show before committing):**
1. Run `tshark -D`, identify the correct capture interface, set `TSHARK_INTERFACE` in `tg_config.py`.
2. Add `curl_cffi` to `requirements.txt` with an appropriate version pin. Confirm `bot_tier2_evasive.py` and `gate1_5_tier2_verify.py` import and run without error.
3. Add a `client_identity_id` column to `session_manifest.csv`'s schema and `db/schema.sql`, distinct from `session_id`. Update `session_orchestrator.py` to run N sessions (3-5) under one shared `client_identity_id`, simulating repeat visits from the same claimed client. `session_id` stays the unique per-connection identifier; `client_identity_id` is the new grouping key.

**Step 2 — Small pilot (20 sessions, not the full run):**
Run human + bot tiers 1-3, ~20 sessions total, including at least one `client_identity_id` repeated 3 times, end-to-end through `build_dataset.py`. Report: are all pcaps non-empty? Does `client_identity_id` correctly group repeated sessions in the output? Is every field populated with a real value (flag anything still stuck at a placeholder, e.g. `quic_transport_param_count` at -1)? Any tshark/curl_cffi errors during the run? **Do not proceed to a larger run until this is reviewed.**

**Step 3 — Multi-hot decision (resolve with the team before continuing):**
Decide whether `supported_groups`/`alpn_protocols` should be multi-hot (richer, needed for spatial-inconsistency detail) or stay single-hashed (matches Basel's original design, simpler). If multi-hot is chosen, update `feature_schema.py` and `build_dataset.py` accordingly and re-run the Step 2 pilot to confirm new fields populate correctly. Document whichever decision is made here in this file so it isn't silently re-litigated later.

**Step 4 — Full generation run (only after Steps 1-3 check out clean):**
Generate the 1,600-session main dataset per the class targets in `MASTER_Implementation_Plan.md` §7 (human: 500, tier1: 400, tier2: 400, tier3: 300 = 1,600). Tier 4 (200 sessions) is generated separately in Phase 5 as the evasion test against D1/D2 — not part of this run, still a stub here, skip it. Log failures/empty pcaps as they happen, not only at the end. Run `build_dataset.py` and report final `dataset.parquet` row count, class balance, and any fields with unexpected null/placeholder rates.

**Step 5 — Consistency layer (the new contribution):**
Using `dataset.parquet`, build expected-combination tables from human-labeled sessions only: for each observed `(tls_version, cipher_suite_order_hash, has_pq_keyshare, alpn, quic_version)` combination, record its frequency. Write a scoring function returning a spatial-inconsistency score for any session, based on how unlikely its combination is under the human-derived distribution — this produces the scoring function for Experiment D1. Keep this in a new `consistency-layer/` directory — do not mix it into Basel's existing files. Before building anything further on top of it, show the scoring function's output distribution on a sample of human vs. bot_tier2/3 sessions, so it can be confirmed the scores actually separate the classes.

**Phase-gating rule:** do not start Phase 6 (live proxy + dashboard) until Experiments A/B/D1/D2 are trained and evaluated, and Phase 5 evasion-resistance testing (Tier-4 adaptive bot vs. D1/D2) is complete. Evasion resistance is a **required primary outcome** for the paper's empirical claim, not an experiment that can be cut under time pressure. If the project falls behind schedule, **cut Phase 6 (live proxy + dashboard) first** — it's valuable for the demo but not load-bearing for the paper's empirical claim. Do not cut or scope down Phase 5 evasion-resistance testing before Phase 6 is already gone.

---

## Instructions for Claude Code

- Read this file plus `Docs/handoff_report.md` and `Docs/MASTER_Implementation_Plan.md` before writing any code.
- Treat anything marked "done" in the handoff report as **written but unvalidated** until you've confirmed it actually runs and produces output — check for real output artifacts (pcaps, dataset files), don't just trust the doc.
- Only modify files you're explicitly asked to change — this is a shared repo with a teammate's existing work in it.
- Flag disagreements between what the docs claim and what the actual code does — don't silently defer to the docs if the code says otherwise.
- New work (the consistency-scoring module) should live in its own clearly separated location (e.g. `consistency-layer/`) rather than being interleaved into Basel's existing files, to keep merge conflicts minimal.
