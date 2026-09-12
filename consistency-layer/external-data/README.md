# External reference data

`llm_agent_study_tls_fingerprints.csv` is a **trimmed** copy (10 of the original ~140 columns —
TLS/ALPN fields only, dropping all IP/geo/HTTP-header columns) of
`Analysis/active_tests_with_TLS_IP_layers.csv` from the public artifact accompanying:

> "On the Internet, Nobody Knows You're an LLM Bot: Unmasking Web Agents with Multi-Layer
> Fingerprinting" (arXiv:2606.30119, June 2026).

Source artifact (freely accessible, no auth required — anonymized for the paper's Open Science
release, IPs already scrubbed by the original authors):
https://anonymous.4open.science/r/On_the_Internet_Nobody_Knows_You-re_an_LLM_Bot_Artifacts-C7BD/

Retrieved: 2026-09-01.

## What it is

1,383 real, passively-captured TLS ClientHello observations (via nginx/tshark, same capture
philosophy as this project) from 16 distinct client types hitting the paper's honeysites:
`Human` (40 rows), plus 15 automated tools — `Selenium`, `Puppeteer`, `Playwright`, `Crawl4AI`
(+`_Stealth`, `+_Undetected_Browser`), `BrowserUse` (+`_Stealth`), `Skyvern`, `OpenClaw`,
`Antropic Claude for Chrome`, `ChatGPT Agent`, `curl`, `wget`, `scrapy`.

Columns kept: `Web Agent`, `Agent Browser`, `Website`, `tls_cipher_pcap`, `tls_ciphers_pcap`,
`SSL_curves_pcap`, `SSL_curve_pcap`, `SSL_alpn_protocol_pcap`, `ssl_protocol_pcap`,
`SSL_session_reused_pcap`.

## Why it's here

Panel feedback on this project: don't rely solely on our own lab-generated dataset — bring in
existing/external data too. This is real, independently-collected, recent (2026) TLS fingerprint
data at the same protocol layer this project studies (unlike the FP-Inconsistent paper referenced
in `CLAUDE.md`, which is browser/JS-layer, not network-layer) — including real observations of the
`0x11ec` PQ codepoint this whole project is built around, from real Chrome 144 and multiple
automation tools.

Used by `external_reference.py` to widen the Step 5 expected-combination table beyond our own
500 synthetic human sessions (see the `source` column it produces — `lab` vs `external_llm_agent_study`).
Not merged into the A/B/D1/D2 training set itself: the automated-tool rows use a different
bot-tier taxonomy than this project's own and aren't directly comparable to `bot_t1`-`bot_t4`;
they're kept as an external validation/reference set, not additional labeled training rows.

## Known granularity mismatch (documented, not silently smoothed over)

Our own pipeline parses the **offered** ALPN list from the raw ClientHello (can be multiple
values, e.g. both `h2` and `http/1.1`). `SSL_alpn_protocol_pcap` in this external data is the
**negotiated** protocol as seen by nginx (always exactly one value). `external_reference.py`
treats a negotiated value as "this protocol was present" — a weaker claim than "this was the
full offered set" — and does not claim to know what else might have been offered but not chosen.
Same caveat applies to `SSL_curves_pcap` vs `supported_groups`: nginx's SSL variables record
what OpenSSL parsed from the ClientHello's supported_groups extension, so this one is a closer
match to our own field, but naming differs (e.g. `prime256v1` is OpenSSL's alias for
`secp256r1`) — see `_CURVE_ALIASES` in `external_reference.py`.
