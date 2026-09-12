"""
Step 5 — expected-combination table.

Builds the joint distribution of (tls_version, has_pq_keyshare, used_http3,
supported_groups multi-hot, alpn multi-hot) that CLAUDE.md's Step 5 calls for,
from human-labeled sessions. Two sources feed it, each tagged so the mix is
auditable:

  - "lab":                     this project's own 500 human sessions (dataset.parquet)
  - "external_llm_agent_study": the 40 real Human rows from external_reference.py

Why both: a table built from only 500 sessions of one Playwright/Chromium
install on one machine reflects one browser/OS/network profile, not real human
diversity — the panel's core concern. The external rows are independently
collected, real (not synthetic), and from a different research team's
infrastructure, so they widen the "what does a real, legitimate client's
protocol combination look like" distribution beyond our own single capture
setup — directly serving the spatial-inconsistency score this table drives.

cipher_suite_order_hash is deliberately NOT part of the combination key here,
even though it's in our own dataset.parquet and named in CLAUDE.md's Step 5
spec: the external data's cipher list uses different naming (OpenSSL cipher
names, not TLS codepoints) and reconstructing a directly comparable ordered
hash across both sources isn't reliable enough to trust. The combination key
here focuses on the PQ/QUIC/group/ALPN fields that are this project's actual
novel contribution; cipher-suite ordering is already covered by Basel's
classical JA4 features in Experiment A/B.
"""
import sys
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from external_reference import load_external_reference
from tg_config import DATASET_PATH

OUTPUT_CSV = Path(__file__).parent / "expected_combinations.csv"

_SG_FIELDS = ["sg_x25519", "sg_secp256r1", "sg_secp384r1", "sg_secp521r1", "sg_x25519mlkem768", "sg_other"]
_ALPN_FIELDS = ["alpn_h2", "alpn_http11", "alpn_h3", "alpn_other"]
COMBINATION_FIELDS = ["tls_version", "has_pq_keyshare", "used_http3"] + _SG_FIELDS + _ALPN_FIELDS


def _lab_human_rows(dataset_path: Path = DATASET_PATH) -> pd.DataFrame:
    df = pd.read_parquet(dataset_path)
    human = df[df["label"] == "human"].copy()
    human["source"] = "lab"
    return human[["source"] + COMBINATION_FIELDS]


def _external_human_rows() -> pd.DataFrame:
    rows = load_external_reference()
    human_rows = [r for r in rows if r["tool_label"] == "Human"]
    if not human_rows:
        return pd.DataFrame(columns=["source"] + COMBINATION_FIELDS)
    df = pd.DataFrame(human_rows)
    return df[["source"] + COMBINATION_FIELDS]


def build_expected_combinations(dataset_path: Path = DATASET_PATH, include_external: bool = True) -> pd.DataFrame:
    """
    Returns a DataFrame, one row per observed combination:
      COMBINATION_FIELDS..., count, count_lab, count_external, probability
    Sorted by count descending. Also writes it to expected_combinations.csv.
    """
    lab = _lab_human_rows(dataset_path)
    parts = [lab]
    if include_external:
        ext = _external_human_rows()
        parts.append(ext)
    combined = pd.concat(parts, ignore_index=True)

    grouped = combined.groupby(COMBINATION_FIELDS)
    table = grouped.size().reset_index(name="count")
    table["count_lab"] = grouped.apply(lambda g: (g["source"] == "lab").sum()).values
    table["count_external"] = grouped.apply(lambda g: (g["source"] == "external_llm_agent_study").sum()).values
    table["probability"] = table["count"] / table["count"].sum()
    table = table.sort_values("count", ascending=False).reset_index(drop=True)

    table.to_csv(OUTPUT_CSV, index=False)
    return table


if __name__ == "__main__":
    table = build_expected_combinations()
    print(f"{len(table)} distinct combinations observed across {table['count'].sum()} human-labeled sessions")
    print(f"  from lab:      {table['count_lab'].sum()}")
    print(f"  from external: {table['count_external'].sum()}")
    print(f"\nSaved to {OUTPUT_CSV}\n")
    print(table.head(10).to_string(index=False))
