from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.analysis import build_attack_graph, correlate_events, find_attack_paths


SAMPLE_PATH = PROJECT_ROOT / "data" / "sample_events" / "d_attack_chain_events.json"


def main() -> None:
    sample = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    events = sample["events"]
    host_map = sample["host_map"]

    steps = correlate_events(events, host_map)
    graph = build_attack_graph(steps)
    paths = find_attack_paths(steps)

    print("Attack steps:")
    print(json.dumps(steps, ensure_ascii=False, indent=2))
    print()
    print("Attack graph:")
    print(json.dumps(graph, ensure_ascii=False, indent=2))
    print()
    print("Attack paths:")
    print(json.dumps(paths, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
