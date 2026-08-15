"""
Bot Tier 4 — Adaptive/Evasion bot using OpenSSL 3.5 with genuine PQ key share.

!! STUB — DO NOT RUN IN PHASE 2 !!

This tier requires a trained model (from Phase 4) to know what signals to evade.
The traffic generation run happens in Phase 5 (evasion testing).

Planned characteristics (to implement in Phase 5):
  - OpenSSL 3.5 CLI client → sends 0x11EC PQ key share (same as real browser)
  - Forced QUIC via aioquic or similar
  - Human-like timing (mimics human_traffic.py delays)
  - Goal: simultaneously match all protocol signals of a human while being a bot

This is the key evasion experiment: measure how much detection accuracy survives
when the attacker has full knowledge of the feature set and deliberately spoofs it.
Partial degradation is an expected and valid research finding.

Label: "bot_t4"
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tg_config import SESSIONS_TIER4


def run_bot_t4_session(session_id: str) -> None:
    """STUB — will implement in Phase 5 after model is trained."""
    raise NotImplementedError(
        "Tier 4 traffic generation is deferred to Phase 5 (evasion testing). "
        "A trained model from Phase 4 is required first. "
        "See system_design_brief_COMPLETE.md Section 6, Step 22 (Phase 5)."
    )


def main(num_sessions: int = SESSIONS_TIER4) -> list[str]:
    """STUB — deferred to Phase 5."""
    raise NotImplementedError(
        "Tier 4 traffic generation is deferred to Phase 5. "
        "Run ml/train_enhanced.py first, then implement this module."
    )


if __name__ == "__main__":
    print(
        "[bot_t4] STUB — Tier 4 adaptive bot is deferred to Phase 5 (evasion testing).\n"
        "         This file reserves the label 'bot_t4' and SESSIONS_TIER4 config value.\n"
        "         Implement after training the Phase 4 model."
    )
    sys.exit(0)
