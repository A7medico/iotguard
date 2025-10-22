# scripts/simulate_stream.py
# -----------------------------------------------------------------------------
# Utility — Generate synthetic feature rows
#
# Purpose
#   - Append benign/attack-like rows to data/features.csv for local testing of
#     the decision loop and dashboards without Suricata.
# -----------------------------------------------------------------------------
import random, time
from pathlib import Path

CSV = Path("data/features.csv")
FEATURES_HEADER = "flows,bytes_total,pkts_total,uniq_src,uniq_dst,syn_ratio,mean_bytes_flow\n"

CSV.parent.mkdir(parents=True, exist_ok=True)
if not CSV.exists() or CSV.read_text(encoding="utf-8").strip() == "":
    CSV.write_text(FEATURES_HEADER, encoding="utf-8")

def benign():
    flows = random.randint(5, 20)
    pkts  = flows * random.randint(2,5)
    bytes_ = pkts * random.randint(40,80)
    uniq_src = random.randint(2,5)
    uniq_dst = uniq_src + random.randint(0,2)
    syn_ratio = round(random.uniform(0.05, 0.25), 2)
    mean_bytes = int(bytes_ / max(flows,1))
    return flows, bytes_, pkts, uniq_src, uniq_dst, syn_ratio, mean_bytes

def attack():
    flows = random.randint(20, 60)
    pkts  = flows * random.randint(3,8)
    bytes_ = pkts * random.randint(60,120)
    uniq_src = random.randint(5,10)
    uniq_dst = random.randint(4,10)
    syn_ratio = round(random.uniform(0.7, 0.98), 2)
    mean_bytes = int(bytes_ / max(flows,1))
    return flows, bytes_, pkts, uniq_src, uniq_dst, syn_ratio, mean_bytes

print("🧪 Simulating rows → data/features.csv (Ctrl-C to stop)")
try:
    while True:
        # 70% benign, 30% attack bursts
        row = attack() if random.random() < 0.3 else benign()
        with CSV.open("a", encoding="utf-8") as f:
            f.write("{},{},{},{},{},{:.2f},{}\n".format(*row))
        time.sleep(random.uniform(0.5, 1.5))
except KeyboardInterrupt:
    print("\nStopped.")
