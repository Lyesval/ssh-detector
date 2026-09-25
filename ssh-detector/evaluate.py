#!/usr/bin/env python3
"""Compare alerts.jsonl against labels.json and print precision / recall / F1 (overall and per rule).

    python evaluate.py sample/alerts.jsonl sample/labels.json

Matching unit = (rule, entity). Duplicate alerts for the same pair count once.
"""
import json
import sys
from collections import defaultdict


def load(path, jsonl=False):
    with open(path) as f:
        rows = [json.loads(l) for l in f if l.strip()] if jsonl else json.load(f)
    return {(r["rule"], r["entity"]) for r in rows}


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1


def main(alerts_path, labels_path):
    got, want = load(alerts_path, jsonl=True), load(labels_path)
    tp, fp, fn = got & want, got - want, want - got
    rules = defaultdict(lambda: [0, 0, 0])
    for r, _ in tp: rules[r][0] += 1
    for r, _ in fp: rules[r][1] += 1
    for r, _ in fn: rules[r][2] += 1
    print(f"{'rule':24}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>7}{'recall':>8}{'F1':>7}")
    for r, (a, b, c) in sorted(rules.items()):
        p, rc, f = prf(a, b, c)
        print(f"{r:24}{a:>4}{b:>4}{c:>4}{p:>7.2f}{rc:>8.2f}{f:>7.2f}")
    p, rc, f = prf(len(tp), len(fp), len(fn))
    print(f"{'OVERALL':24}{len(tp):>4}{len(fp):>4}{len(fn):>4}{p:>7.2f}{rc:>8.2f}{f:>7.2f}")
    for r, e in sorted(fp): print(f"  false positive: {r} on {e}")
    for r, e in sorted(fn): print(f"  missed:         {r} on {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
