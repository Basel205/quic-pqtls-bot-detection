"""
Step 5 — temporal-inconsistency scoring function. Feeds Experiment D2
(adds to D1's spatial score).

Measures how much a session's protocol-layer fingerprint drifts from the
*other* sessions claiming the same client_identity_id (the repeat-visit
grouping session_orchestrator.py already produces, 3-5 sessions per group).
A real device visiting repeatedly should look like itself each time; a bot
whose tooling/fingerprint isn't stable across "repeat visits" (different
proxy, different automation profile, etc.) will drift.

TEMPORAL_FIELDS deliberately excludes cipher_suite_order_hash and
extension_order_hash even though they're the most granular fields available:
real browsers randomize cipher/extension order per-connection via GREASE
(confirmed empirically in Step 5's spatial-score checkpoint — extension_order_hash
is unique across 100% of our own human sessions, including within the same
client_identity_id group), so treating them as "should stay stable" would
flag genuine repeat visits from one real device as inconsistent just as often
as an actual bot — pure noise, not signal. ja4_fingerprint_hash is included
instead: JA4 sorts ciphers/extensions before hashing specifically to be
GREASE-order-invariant, so it SHOULD stay stable for the same device/config
across repeat visits, unlike the raw order-sensitive hashes.
"""
import sys
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from tg_config import DATASET_PATH, MANIFEST_PATH

TEMPORAL_FIELDS = [
    "tls_version", "has_pq_keyshare", "used_http3", "ja4_fingerprint_hash",
    "quic_version", "quic_transport_param_count",
    "sg_x25519", "sg_secp256r1", "sg_secp384r1", "sg_secp521r1", "sg_x25519mlkem768", "sg_other",
    "alpn_h2", "alpn_http11", "alpn_h3", "alpn_other",
]


def compute_temporal_scores(df: pd.DataFrame, manifest_path: Path = MANIFEST_PATH) -> pd.Series:
    """
    Returns a Series aligned to df.index: for each session, the mean fraction
    of TEMPORAL_FIELDS that mismatch when compared pairwise against every
    other session sharing the same client_identity_id. 0 = perfectly
    consistent with the rest of its group; 1 = disagrees with every sibling
    on every field. Sessions whose client_identity_id has no siblings
    (shouldn't happen given the 3-5 batch design, but handled defensively)
    score 0 — no repeat-visit evidence to call inconsistent.
    """
    manifest = pd.read_csv(manifest_path)[["session_id", "client_identity_id"]]
    merged = df.merge(manifest, on="session_id", how="left")

    scores = pd.Series(0.0, index=df.index)
    n_fields = len(TEMPORAL_FIELDS)

    for _, group in merged.groupby("client_identity_id"):
        n = len(group)
        if n <= 1:
            continue
        vals = group[TEMPORAL_FIELDS].to_numpy()
        idxs = group.index.to_numpy()
        for i in range(n):
            mismatches = 0
            for j in range(n):
                if i == j:
                    continue
                mismatches += int((vals[i] != vals[j]).sum())
            scores.loc[idxs[i]] = mismatches / (n_fields * (n - 1))

    return scores


if __name__ == "__main__":
    df = pd.read_parquet(DATASET_PATH)
    df["temporal_inconsistency_score"] = compute_temporal_scores(df)

    out = df[["session_id", "label", "temporal_inconsistency_score"]]
    out.to_csv(Path(__file__).parent / "d2_temporal_scores.csv", index=False)

    print("Temporal inconsistency score distribution by label:\n")
    print(df.groupby("label")["temporal_inconsistency_score"].describe().to_string())
