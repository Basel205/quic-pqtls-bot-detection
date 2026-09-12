"""
Experiment B — Enhanced: classical + PQ key-share + QUIC + behavioral timing features.
See train_utils.py for the shared training/evaluation logic.
"""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from train_utils import train_and_evaluate

if __name__ == "__main__":
    result = train_and_evaluate("B_enhanced")
    print(json.dumps({k: v for k, v in result.items() if k != "features"}, indent=2))
