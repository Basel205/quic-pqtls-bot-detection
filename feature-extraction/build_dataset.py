"""
Feature extraction pipeline — assembles dataset.parquet from pcap_store/.

Data flow (per system_design_brief_COMPLETE.md Section 5):
  For each pcap in pcap_store/:
    1. pq_detector.extract_pq_features_from_pcap(pcap)
    2. quic_parser.extract_quic_features_from_pcap(pcap)
    3. timing_extractor.extract_timing_features(pcap)
    4. ja4_extractor.extract_ja4(pcap)
    5. ja4h_extractor.extract_ja4h(session_id, access_log_path)
    6. Join with session_manifest.csv on session_id
    7. Write FeatureVector to SQLite (features table)
  Export all rows → dataset.parquet

Usage:
  python build_dataset.py
  python build_dataset.py --pcap capture/pcap_store/some_session.pcap  # single file
"""
import argparse
import csv
import hashlib
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

# Bootstrap paths — must come before any project imports
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from feature_schema import FeatureVector
from pq_detector    import extract_pq_features_from_pcap
from quic_parser    import extract_quic_features_from_pcap
from timing_extractor import extract_timing_features
from ja4_extractor  import extract_ja4
from ja4h_extractor import extract_ja4h
from config import (
    PCAP_STORE, DB_PATH, DATASET_PATH, MANIFEST_PATH,
)

ACCESS_LOG = Path(__file__).parent.parent / "target-site" / "logs" / "access.log"


def extract_features_for_pcap(pcap_path: Path, session_id: str, label: str) -> FeatureVector:
    """Run all extractors on a single pcap and return a complete FeatureVector."""

    pq_feats      = extract_pq_features_from_pcap(str(pcap_path))
    quic_feats    = extract_quic_features_from_pcap(str(pcap_path))
    timing_feats  = extract_timing_features(str(pcap_path))
    ja4_feats     = extract_ja4(str(pcap_path))
    ja4h_feats    = extract_ja4h(session_id, str(ACCESS_LOG))

    return FeatureVector(
        session_id=session_id,

        # Classical TLS (from JA4 and pq_detector)
        ja4_fingerprint_hash    = ja4_feats["ja4_fingerprint_hash"],
        tls_version             = pq_feats["tls_version"],
        cipher_suite_count      = pq_feats["cipher_suite_count"],
        cipher_suite_order_hash = pq_feats["cipher_suite_order_hash"],
        extension_count         = pq_feats["extension_count"],
        extension_order_hash    = pq_feats["extension_order_hash"],
        supported_groups_hash   = pq_feats["supported_groups_hash"],
        alpn_hash               = pq_feats["alpn_hash"],

        # Novel PQ/QUIC signals
        has_pq_keyshare          = pq_feats["has_pq_keyshare"],
        pq_keyshare_data_len     = pq_feats["pq_keyshare_data_len"],
        used_http3               = quic_feats["used_http3"],
        quic_version             = quic_feats["quic_version"],
        quic_transport_param_count = quic_feats["quic_transport_param_count"],
        quic_conn_id_len         = quic_feats["quic_conn_id_len"],

        # Behavioral
        inter_request_timing_cv  = timing_feats["inter_request_timing_cv"],
        record_layer_timing_p50  = timing_feats["record_layer_timing_p50"],
        session_request_count    = timing_feats["session_request_count"],
        ja4h_fingerprint_hash    = ja4h_feats["ja4h_fingerprint_hash"],

        label=label,
    )


def load_manifest() -> dict[str, str]:
    """Load session_manifest.csv → {session_id: label}"""
    manifest: dict[str, str] = {}
    if not MANIFEST_PATH.exists():
        print(f"[build_dataset] WARNING: manifest not found at {MANIFEST_PATH}")
        return manifest
    with open(MANIFEST_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            manifest[row["session_id"]] = row["label"]
    return manifest


def write_to_sqlite(fv: FeatureVector) -> None:
    """Upsert a FeatureVector row into the SQLite features table."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        d = fv.to_dict()
        d.pop("session_id")
        cols   = ", ".join(d.keys())
        placeholders = ", ".join("?" for _ in d)
        vals   = list(d.values())
        conn.execute(
            f"""INSERT OR REPLACE INTO features (session_id, {cols})
                VALUES (?, {placeholders})""",
            [fv.session_id] + vals,
        )
        conn.commit()
    finally:
        conn.close()


def build_dataset(pcap_dir: Path = PCAP_STORE, single_pcap: Path | None = None) -> None:
    """
    Main pipeline: process all pcaps (or just one), write parquet + SQLite.
    """
    manifest = load_manifest()
    rows: list[dict] = []

    if single_pcap:
        pcaps = [single_pcap]
    else:
        pcaps = sorted(pcap_dir.glob("*.pcap"))

    if not pcaps:
        print(f"[build_dataset] No pcaps found in {pcap_dir}")
        return

    for pcap_path in pcaps:
        session_id = pcap_path.stem
        label      = manifest.get(session_id)

        if label is None:
            print(f"[build_dataset] SKIP {session_id} — not in manifest")
            continue

        if pcap_path.stat().st_size == 0:
            print(f"[build_dataset] SKIP {session_id} — empty pcap")
            continue

        print(f"[build_dataset] Processing {session_id} (label={label})...")
        try:
            fv = extract_features_for_pcap(pcap_path, session_id, label)
            write_to_sqlite(fv)
            rows.append(fv.to_dict())
        except Exception as e:
            print(f"[build_dataset] ERROR on {session_id}: {e}")
            continue

    if not rows:
        print("[build_dataset] No rows produced — check pcaps and manifest.")
        return

    # Write parquet
    df = pd.DataFrame(rows)
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(DATASET_PATH, index=False)
    print(f"\n[build_dataset] Done. {len(rows)} sessions → {DATASET_PATH}")
    print(f"  Columns: {list(df.columns)}")
    print(f"  has_pq_keyshare distribution:\n{df.groupby(['label','has_pq_keyshare']).size().to_string()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build dataset.parquet from pcaps")
    parser.add_argument("--pcap", type=Path, default=None, help="Single pcap file to process")
    args = parser.parse_args()

    build_dataset(single_pcap=args.pcap)
