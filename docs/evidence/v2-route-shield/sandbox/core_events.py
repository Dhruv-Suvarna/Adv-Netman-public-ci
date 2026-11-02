#!/usr/bin/env python3
"""Every kernel route event of a client /64 on the FRR cores, and whether its /63 cover was installed at that instant.
usage: core_events.py <rundir>"""
import re, sys, datetime, bisect, collections
d = sys.argv[1]
ev = []
for l in open(f"{d}/events.log"):
    a = l.split(None, 1)
    try: ev.append((float(a[0]), a[1].strip()[:90]))
    except Exception: pass
ts = [e[0] for e in ev]
bad = total = 0
for core in ("c3", "c4"):
    cover = {}; where = collections.Counter(); unc = []
    for l in open(f"{d}/mon_{core}.log"):
        m = re.match(r"\[(\S+)\] (Deleted )?(2001:db8:(?:10|20|30)::/(63|64))", l.replace("\0", ""))
        if not m: continue
        t = datetime.datetime.fromisoformat(m.group(1)).replace(tzinfo=datetime.timezone.utc).timestamp()
        deleted, prefix, length = bool(m.group(2)), m.group(3), m.group(4)
        if length == "63":
            cover[prefix] = not deleted; continue
        if not deleted: continue
        total += 1
        step = re.sub(r"^[FBDPW]\d+", "X", ev[max(bisect.bisect(ts, t) - 1, 0)][1])[:60]
        if cover.get(prefix.replace("/64", "/63")):
            where["covered   | " + step] += 1
        else:
            where["UNCOVERED | " + step] += 1; bad += 1
    print(f"== {core}")
    for k, v in sorted(where.items()): print(f"  {v:4d}  {k}")
print(f"client /64 route replacements on the cores: {total}   without a cover: {bad}")
print("CORE VERDICT:", "PASS" if bad == 0 else "FAIL")
