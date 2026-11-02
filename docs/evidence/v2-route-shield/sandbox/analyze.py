#!/usr/bin/env python3
"""Loss accounting for a mig.py run.  A probe is lost when its sequence number never got a reply; a flow with no samples fails.
usage: analyze.py <outdir> [-v]"""
import glob, os, re, sys
out, verbose = sys.argv[1], "-v" in sys.argv
events = []
for line in open(f"{out}/events.log"):
    parts = line.split(None, 2)
    if len(parts) == 3: events.append((float(parts[0]), parts[1], parts[2].strip()))
def phase(t):
    prev = [e for e in events if e[0] <= t]
    return f"{prev[-1][1]} {prev[-1][2][:44]}" if prev else "before-start"
REPLY = re.compile(r"\[(\d+\.\d+)\] \d+ bytes from .*seq=(\d+)")
prod = {"probes": 0, "lost": 0}; diag = {"probes": 0, "lost": 0}; rows = []; bad_flows = []; per_cycle = {}
for cdir in sorted(glob.glob(f"{out}/c[0-9][0-9]") + glob.glob(f"{out}/failed")):
    c = os.path.basename(cdir); per_cycle[c] = [0, 0, 0, 0]
    for path in sorted(glob.glob(f"{cdir}/*.log")):
        name = os.path.basename(path)[:-4]; rep = {}
        for line in open(path, errors="replace"):
            m = REPLY.search(line)
            if m: rep[int(m.group(2))] = float(m.group(1))
        is_diag = name.startswith("diag")
        if not rep:
            (rows if is_diag else bad_flows).append(f"{c} {name}: NO SAMPLES"); continue
        lo, hi = min(rep), max(rep)
        if hi - lo > 60000: bad_flows.append(f"{c} {name}: sequence wrapped, shorten the cycle")
        miss = [s for s in range(lo, hi) if s not in rep]
        bucket = diag if is_diag else prod
        bucket["probes"] += hi - lo + 1; bucket["lost"] += len(miss)
        per_cycle[c][2 if is_diag else 0] += hi - lo + 1; per_cycle[c][3 if is_diag else 1] += len(miss)
        if miss:
            step = 0.1 if is_diag or name.endswith("4") else (0.02 if "rev" in name else 0.01); where = {}
            for s in miss:
                before = max(q for q in rep if q < s); where.setdefault(phase(rep[before] + (s - before) * step), []).append(s)
            rows.append(f"{c} {name}: lost {len(miss)} of {hi - lo + 1}  " + "; ".join(f"[{k}] x{len(v)}" for k, v in where.items()))
        elif verbose: rows.append(f"{c} {name}: 0 of {hi - lo + 1}")
print("== sequence-numbered probes"); [print("  ", r) for r in rows]
for c, (p, l, dp, dl) in per_cycle.items(): print(f"   {c}: production {l}/{p} lost   diagnostic {dl}/{dp} lost")
print(f"   PRODUCTION TRANSIT: probes {prod['probes']} lost {prod['lost']}    DIAGNOSTIC (device-originated): probes {diag['probes']} lost {diag['lost']}")
print("== long-lived TCP sessions"); tcp_bad = 0
for path in sorted(glob.glob(f"{out}/*_tcp[46].log")):
    lines = open(path).read().split("\n"); name = os.path.basename(path)[:-4]
    close = [l for l in lines if l.startswith("CLOSE")]; dead = [l for l in lines if l.startswith("DEAD")]; stall = [l for l in lines if l.startswith("STALL")]
    opened = sum(l.startswith("OPEN") for l in lines)
    ok = len(close) == 1 and not dead and opened == 1 and close[0].split()[2] == close[0].split()[3]
    tcp_bad += (not ok)
    print(f"   {name}: {'UNINTERRUPTED' if ok else 'BROKEN'} {close[0] if close else dead or 'no CLOSE line'}  stalls>250ms: {len(stall)} (informational)")
print("== repeated new HTTP sessions"); http_bad = 0
for path in sorted(glob.glob(f"{out}/*_http[46].log")):
    lines = open(path).read().split("\n"); name = os.path.basename(path)[:-4]
    close = [l for l in lines if l.startswith("CLOSE")]; fail = [l for l in lines if l.startswith("FAIL")]; slow = [l for l in lines if l.startswith("SLOW")]
    ok = len(close) == 1 and not fail and int(close[0].split()[2]) > 0
    http_bad += (not ok)
    print(f"   {name}: {'ALL OK' if ok else 'FAILURES'} {close[0] if close else 'no CLOSE line'}  slow>400ms: {len(slow)} (informational)" + ("  " + "; ".join(f"FAIL@[{phase(float(l.split()[1]))}]" for l in fail[:6]) if fail else ""))
fwd = sum(1 for e in events if "stage12 final-config" in e[2]); back = sum(1 for e in events if "baseline-restored True" in e[2])
drains = sum(1 for e in events if e[2].startswith("verified") and "drain" in e[1]); restores = sum(1 for e in events if e[2].startswith("verified") and "restore" in e[1])
print(f"== completed: forward {fwd}  rollback {back}  drains {drains}  restores {restores}   failed-events: {[e[2][:200] for e in events if e[1] == 'FAILED']}")
verdict = prod["lost"] == 0 and not bad_flows and not tcp_bad and not http_bad and not any(e[1] == "FAILED" for e in events)
print("   flows without evidence:", bad_flows or "none")
print("VERDICT:", "PASS (production transit loss 0, TCP uninterrupted, HTTP all successful)" if verdict else "FAIL")
