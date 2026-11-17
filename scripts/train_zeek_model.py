"""Train the flow classifier on Zeek conn.log output of the CIC-IDS2017 PCAPs (what production sees).

    .venv/bin/python scripts/train_zeek_model.py datasets/cicids2017/zeek "datasets/cicids2017/TrafficLabelling "

Why: a model trained on CICFlowMeter CSVs does not transfer to Zeek. Example: CICFlowMeter counts Ethernet
padding as payload, so a SYN->RST port-scan probe shows 6 response bytes in the CSVs but 0 in Zeek; the
CSV-trained model learned the artifact and caught 3.5% of Friday's port scans on Zeek output.

Labels: CIC TrafficLabelling CSVs matched to Zeek connections (scripts/eval_zeek.py). Split at the
connection level (stratified 70/15/15), then the training set alone is de-duplicated. Test metrics are
reported on all test connections (the real traffic mix) and on test connections whose feature vector never
appears in training (the strict, no-memorisation number). Test connection uids are written out so the full
pipeline (rules + model) can be scored on held-out connections with eval_zeek.py --only-uids.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

import numpy as np
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from eval_zeek import corrected_label, label_flow, load_cic_index  # noqa: E402
from nids_agent.features import FEATURE_NAMES, flow_features  # noqa: E402
from nids_agent.model import ForestModel  # noqa: E402
from nids_agent.zeek import load_conn_log  # noqa: E402
from train_model import (CLASSES, SEED, binary_rates, dedupe, export, make_forest,  # noqa: E402
                         pick_threshold, write_baseline)

# Zeek conn.log stem -> CIC TrafficLabelling CSV globs for the same day
DAYS = {
    "Monday-WorkingHours": ["Monday-*.csv"],
    "Tuesday-WorkingHours": ["Tuesday-*.csv"],
    "Wednesday-workingHours": ["Wednesday-*.csv"],
    "Thursday-WorkingHours": ["Thursday-*.csv"],
    "Friday-WorkingHours": ["Friday-*.csv"],
}


def load_labeled(zeek_dir, labels_dir, cache):
    if os.path.exists(cache):
        d = np.load(cache, allow_pickle=False)
        return d["X"], d["y"], d["uid"], d["day"]
    xs, ys, uids, days = [], [], [], []
    for day, globs in DAYS.items():
        path = os.path.join(zeek_dir, f"{day}.conn.log")
        if not os.path.exists(path):
            continue
        index, n_cic = load_cic_index([os.path.join(labels_dir, g) for g in globs])
        flows = [f for f in load_conn_log(path) if f["protocol"] in ("TCP", "UDP") and f["timestamp"]]
        n_match = 0
        for flow in flows:
            label = label_flow(flow, index)
            if label is None:
                continue
            label = corrected_label(flow, label)  # documented CIC labeling errors (eval_zeek.KNOWN_LABEL_ERRORS)
            n_match += 1
            xs.append(flow_features(flow))
            ys.append(CLASSES.index(label))
            uids.append(flow["flow_id"])
            days.append(day)
        print(f"{day}: {len(flows)} TCP/UDP connections, {n_match} labeled ({n_match / max(len(flows), 1):.1%})")
    X = np.asarray(xs, dtype=np.float32)
    y = np.asarray(ys, dtype=np.int8)
    uid = np.asarray(uids)
    day = np.asarray(days)
    np.savez(cache, X=X, y=y, uid=uid, day=day)
    return X, y, uid, day


def stratify_labels(y):
    # train_test_split needs >= 2 members per stratum; put singleton classes in the BENIGN stratum.
    # Only the stratification groups change; labels stay as they are.
    counts = np.bincount(y, minlength=len(CLASSES))
    return np.where(counts[y] >= 2, y, CLASSES.index("BENIGN"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zeek_dir")
    ap.add_argument("labels_dir")
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "models", "flow_classifier.json.gz"))
    ap.add_argument("--target-fpr", type=float, default=0.005)
    ap.add_argument("--trees", type=int, default=30)
    ap.add_argument("--max-depth", type=int, default=18)
    ap.add_argument("--min-leaf", type=int, default=5)
    args = ap.parse_args()
    benign = CLASSES.index("BENIGN")

    t0 = time.time()
    present = [d for d in DAYS if os.path.exists(os.path.join(args.zeek_dir, f"{d}.conn.log"))]
    cache = os.path.join(args.zeek_dir, "labeled_fixed_" + "_".join(d.split("-")[0] for d in present) + ".npz")
    X, y, uid, day = load_labeled(args.zeek_dir, args.labels_dir, cache)
    print(f"{len(y)} labeled connections from {sorted(set(day.tolist()))} in {time.time() - t0:.0f}s")
    print("classes:", {CLASSES[c]: int(n) for c, n in enumerate(np.bincount(y, minlength=len(CLASSES))) if n})

    idx = np.arange(len(y))
    tr, rest = train_test_split(idx, test_size=0.30, stratify=stratify_labels(y), random_state=SEED)
    va, te = train_test_split(rest, test_size=0.50, stratify=stratify_labels(y[rest]), random_state=SEED)
    X_tr, y_tr = dedupe(X[tr], y[tr])
    print(f"train: {len(tr)} connections -> {len(y_tr)} unique; validation {len(va)}; test {len(te)}")

    t0 = time.time()
    forest = make_forest(args).fit(X_tr, y_tr)
    print(f"trained in {time.time() - t0:.0f}s")
    bcol = list(forest.classes_).index(benign)

    def score(Xs):
        return 1.0 - forest.predict_proba(Xs)[:, bcol]

    threshold = pick_threshold(score(X[va]), y[va], benign, args.target_fpr)
    te_score = score(X[te])

    # Strict subset: test vectors that never occur in the training data.
    train_rows = {row.tobytes() for row in X_tr}
    unseen = np.array([X[i].tobytes() not in train_rows for i in te])

    def per_class(mask):
        out = {}
        for c in np.unique(y[te][mask]):
            sel = mask & (y[te] == c)
            out[CLASSES[c]] = {"n": int(sel.sum()), "flagged": round(float(np.mean(te_score[sel] >= threshold)), 4)}
        return out

    all_mask = np.ones(len(te), dtype=bool)
    metrics = {
        "training_source": "zeek conn.log (CIC-IDS2017 PCAPs, labels matched from TrafficLabelling CSVs, "
                           "known labeling errors corrected)",
        "days": sorted(set(day.tolist())),
        "labeled_connections": int(len(y)),
        "split_connections": {"train": int(len(tr)), "train_unique": int(len(y_tr)),
                              "validation": int(len(va)), "test": int(len(te)), "test_unseen_vectors": int(unseen.sum())},
        "threshold": threshold, "target_fpr": args.target_fpr,
        "test_all": binary_rates(te_score, y[te], threshold, benign),
        "test_unseen_vectors": binary_rates(te_score[unseen], y[te][unseen], threshold, benign),
        "test_per_class_flagged_all": per_class(all_mask),
        "test_per_class_flagged_unseen": per_class(unseen),
        "hyperparameters": {"trees": args.trees, "max_depth": args.max_depth, "min_leaf": args.min_leaf},
    }

    artifact = export(forest, threshold, metrics, args.out,
                      dataset="CIC-IDS2017 PCAPs via Zeek 9.0.1 conn.log, " + ", ".join(metrics["days"]),
                      training_source="zeek")
    model = ForestModel(artifact)
    sample = np.random.default_rng(SEED).choice(len(te), size=min(2000, len(te)), replace=False)
    metrics["parity_max_abs_diff"] = float(max(
        abs(model.predict_proba(X[te[i]].astype(float).tolist())[benign] - (1 - te_score[i])) for i in sample))
    with open(args.out.replace(".json.gz", ".metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    write_baseline(X[tr], y[tr], os.path.join(os.path.dirname(args.out), "baseline.json"))
    test_uids = os.path.join(args.zeek_dir, "test_uids.txt")
    with open(test_uids, "w", encoding="utf-8") as f:
        f.write("\n".join(uid[te].tolist()) + "\n")
    print(f"exported {args.out} ({os.path.getsize(args.out) / 1e6:.1f} MB), parity {metrics['parity_max_abs_diff']:.1e}; "
          f"test uids -> {test_uids}")
    print(json.dumps({k: metrics[k] for k in ("threshold", "test_all", "test_unseen_vectors",
                                               "test_per_class_flagged_all", "test_per_class_flagged_unseen")}, indent=2))


if __name__ == "__main__":
    main()
