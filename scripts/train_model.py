"""Train, evaluate and export the flow classifier on CIC-IDS2017.

    .venv/bin/python scripts/train_model.py datasets/cicids2017/MachineLearningCVE

Steps: convert CSVs -> pipeline flows -> features (nids_agent.features, same code as inference),
drop exact duplicates, stratified 70/15/15 train/validation/test split, train a random forest,
pick the ATTACK threshold on validation for a target false-positive rate, evaluate once on test,
and export a gzipped-JSON artifact that nids_agent/model.py runs without scikit-learn.

Optional --compare-full trains the same forest on all 78 CICFlowMeter columns to show how much
accuracy the portable feature set gives up.
"""
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import json
import os
import sys
import time
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from cicids2017 import LABEL_MAP, iter_flows, normalize_label  # noqa: E402
from nids_agent.features import FEATURE_NAMES, flow_features  # noqa: E402
from nids_agent.model import ForestModel  # noqa: E402

CLASSES = list(LABEL_MAP)
SEED = 42


def load_core(csv_dir: str, cache: str):
    if os.path.exists(cache):
        d = np.load(cache)
        return d["X"], d["y"]
    xs, ys, chunk_x, chunk_y = [], [], [], []
    for flow in iter_flows(csv_dir):
        chunk_x.append(flow_features(flow))
        chunk_y.append(CLASSES.index(flow["cic_label"]))
        if len(chunk_x) == 200_000:
            xs.append(np.asarray(chunk_x, dtype=np.float32)); ys.append(np.asarray(chunk_y, dtype=np.int8))
            chunk_x, chunk_y = [], []
    xs.append(np.asarray(chunk_x, dtype=np.float32)); ys.append(np.asarray(chunk_y, dtype=np.int8))
    X, y = np.concatenate(xs), np.concatenate(ys)
    np.savez(cache, X=X, y=y)
    return X, y


def load_full(csv_dir: str, cache: str):
    if os.path.exists(cache):
        d = np.load(cache)
        return d["X"], d["y"]
    xs, ys = [], []
    for path in sorted(glob.glob(os.path.join(csv_dir, "*.csv"))):
        with open(path, "r", encoding="latin-1", newline="") as f:
            reader = csv.reader(f)
            header = [h.strip() for h in next(reader)]
            li = header.index("Label")
            rows, labels = [], []
            for row in reader:
                labels.append(CLASSES.index(normalize_label(row[li])))
                rows.append([c for i, c in enumerate(row) if i != li])
        X = np.asarray(rows, dtype=np.float64)
        X[~np.isfinite(X)] = -1.0
        xs.append(X.astype(np.float32)); ys.append(np.asarray(labels, dtype=np.int8))
    X, y = np.concatenate(xs), np.concatenate(ys)
    np.savez(cache, X=X, y=y)
    return X, y


def dedupe(X, y):
    rows = np.concatenate([X, y[:, None].astype(np.float32)], axis=1)
    _, keep = np.unique(rows, axis=0, return_index=True)
    keep.sort()
    return X[keep], y[keep]


def split(X, y):
    # Classes too small to stratify (Heartbleed: 11 flows) still get members in every split with these sizes.
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=SEED)
    X_va, X_te, y_va, y_te = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=SEED)
    return X_tr, y_tr, X_va, y_va, X_te, y_te


def binary_rates(attack_score, y, threshold, benign):
    pred = attack_score >= threshold
    true = y != benign
    tp = int(np.sum(pred & true)); fp = int(np.sum(pred & ~true))
    fn = int(np.sum(~pred & true)); tn = int(np.sum(~pred & ~true))
    recall = tp / max(tp + fn, 1); fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {"recall": round(recall, 4), "fpr": round(fpr, 5), "precision": round(precision, 4),
            "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def pick_threshold(attack_score, y, benign, target_fpr):
    """Lowest threshold (highest recall) whose validation FPR <= target_fpr."""
    benign_scores = np.sort(attack_score[y == benign])
    # Allow at most floor(target * n) benign flows at/above the threshold.
    k = int(np.floor(target_fpr * len(benign_scores)))
    cand = benign_scores[len(benign_scores) - k - 1] if k < len(benign_scores) else 0.0
    threshold = float(np.nextafter(cand, np.inf))  # strictly above the (k+1)-th highest benign score
    return max(threshold, 1e-6)


def make_forest(args):
    return RandomForestClassifier(
        n_estimators=args.trees, max_depth=args.max_depth, min_samples_leaf=args.min_leaf,
        n_jobs=-1, random_state=SEED,
    )


def export(forest, threshold, metrics, out_path,
           dataset="CIC-IDS2017 MachineLearningCVE (sha256 c3f26274...7928)", training_source="cicflowmeter"):
    trees = []
    for est in forest.estimators_:
        t = est.tree_
        leaves = {}
        for node in np.where(t.children_left == -1)[0]:
            dist = t.value[node][0]
            dist = dist / dist.sum()
            # est.classes_ are indices into CLASSES (all classes present in train).
            leaves[str(int(node))] = [[int(forest.classes_[c]), round(float(p), 5)] for c, p in enumerate(dist) if p > 0]
        trees.append({
            "f": [int(v) if v >= 0 else 0 for v in t.feature],
            "t": [float(v) for v in t.threshold],
            "l": [int(v) for v in t.children_left],
            "r": [int(v) for v in t.children_right],
            "v": leaves,
        })
    artifact = {
        "type": "random_forest",
        "version": datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset,
        "training_source": training_source,
        "feature_names": FEATURE_NAMES,
        "classes": CLASSES,
        "class_map": {k: list(v) for k, v in LABEL_MAP.items()},
        "threshold": threshold,
        "metrics": metrics,
        "trees": trees,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8", compresslevel=9) as f:
        json.dump(artifact, f, separators=(",", ":"))
    return artifact


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_dir")
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "models", "flow_classifier.json.gz"))
    ap.add_argument("--target-fpr", type=float, default=0.005, help="max validation false-positive rate")
    ap.add_argument("--trees", type=int, default=30)
    ap.add_argument("--max-depth", type=int, default=18)
    ap.add_argument("--min-leaf", type=int, default=5)
    ap.add_argument("--compare-full", action="store_true")
    ap.add_argument("--mask-iat-frac", type=float, default=0.5,
                    help="fraction of training rows duplicated with IAT fields missing, so the model also works on "
                         "sources without inter-arrival times (e.g. Zeek conn.log); 0 disables")
    ap.add_argument("--test-sample", default=os.path.join(ROOT, "datasets", "cicids2017", "test_sample.jsonl"),
                    help="write a stratified sample of TEST flows here for end-to-end pipeline runs")
    args = ap.parse_args()
    cache_dir = os.path.dirname(os.path.abspath(args.csv_dir.rstrip("/")))
    benign = CLASSES.index("BENIGN")

    t0 = time.time()
    X, y = load_core(args.csv_dir, os.path.join(cache_dir, "core_features.npz"))
    n_raw = len(y)
    X, y = dedupe(X, y)
    # Feature vectors that appear with more than one label cannot be separated by any model on these features.
    _, inv, counts = np.unique(X, axis=0, return_inverse=True, return_counts=True)
    labels_per_vec = np.zeros(counts.shape[0], dtype=np.int16)
    np.add.at(labels_per_vec, inv.ravel(), 1)
    ambiguous = int(np.sum(labels_per_vec[inv.ravel()] > 1))
    print(f"loaded {n_raw} flows, {len(y)} unique ({ambiguous} share features with another label) "
          f"in {time.time() - t0:.0f}s")

    X_tr, y_tr, X_va, y_va, X_te, y_te = split(X, y)
    iat_cols = [FEATURE_NAMES.index("iat_mean"), FEATURE_NAMES.index("iat_std")]

    def without_iat(Xs):
        Xs = Xs.copy()
        Xs[:, iat_cols] = -1.0
        return Xs

    X_tr_orig, y_tr_orig = X_tr, y_tr  # baseline profile is fitted on real (un-augmented) rows
    if args.mask_iat_frac > 0:
        rng_aug = np.random.default_rng(SEED)
        pick = rng_aug.random(len(y_tr)) < args.mask_iat_frac
        X_tr = np.concatenate([X_tr, without_iat(X_tr[pick])])
        y_tr = np.concatenate([y_tr, y_tr[pick]])
        # Threshold is picked on validation with both views, so it holds for either kind of source.
        X_va = np.concatenate([X_va, without_iat(X_va)])
        y_va = np.concatenate([y_va, y_va])
    t0 = time.time()
    forest = make_forest(args).fit(X_tr, y_tr)
    print(f"trained {args.trees} trees on {len(y_tr)} flows in {time.time() - t0:.0f}s")

    def scores(Xs):
        proba = forest.predict_proba(Xs)
        return 1.0 - proba[:, list(forest.classes_).index(benign)], proba

    va_score, _ = scores(X_va)
    threshold = pick_threshold(va_score, y_va, benign, args.target_fpr)
    te_score, te_proba = scores(X_te)

    test = binary_rates(te_score, y_te, threshold, benign)
    test_no_iat = binary_rates(scores(without_iat(X_te))[0], y_te, threshold, benign)
    at_fpr = {}
    for fpr in (0.001, 0.005, 0.01):
        thr = pick_threshold(va_score, y_va, benign, fpr)
        at_fpr[str(fpr)] = binary_rates(te_score, y_te, thr, benign)
    # Per-class report: attack class = top attack probability when flagged, else BENIGN.
    attack_cols = [i for i, c in enumerate(forest.classes_) if c != benign]
    top_attack = np.asarray(forest.classes_)[attack_cols][np.argmax(te_proba[:, attack_cols], axis=1)]
    y_pred = np.where(te_score >= threshold, top_attack, benign)
    present = sorted(set(y_te.tolist()) | set(y_pred.tolist()))
    report = classification_report(y_te, y_pred, labels=present, target_names=[CLASSES[i] for i in present],
                                   output_dict=True, zero_division=0)
    per_class = {k: {m: round(v[m], 4) for m in ("precision", "recall", "f1-score", "support")}
                 for k, v in report.items() if k in CLASSES}

    metrics = {
        "split": {"train": int(len(y_tr)), "validation": int(len(y_va)), "test": int(len(y_te))},
        "unique_flows": int(len(y)), "raw_flows": int(n_raw), "ambiguous_flows": ambiguous,
        "threshold": threshold, "target_fpr": args.target_fpr,
        "test_binary": test, "test_binary_without_iat": test_no_iat, "test_binary_at_validation_fpr": at_fpr, "test_per_class": per_class,
        "hyperparameters": {"trees": args.trees, "max_depth": args.max_depth, "min_leaf": args.min_leaf,
                            "mask_iat_frac": args.mask_iat_frac},
    }

    if args.compare_full:
        t0 = time.time()
        Xf, yf = dedupe(*load_full(args.csv_dir, os.path.join(cache_dir, "full_features.npz")))
        Xf_tr, yf_tr, Xf_va, yf_va, Xf_te, yf_te = split(Xf, yf)
        ff = make_forest(args).fit(Xf_tr, yf_tr)
        bi = list(ff.classes_).index(benign)
        thr_f = pick_threshold(1 - ff.predict_proba(Xf_va)[:, bi], yf_va, benign, args.target_fpr)
        metrics["comparison_all_78_features"] = binary_rates(1 - ff.predict_proba(Xf_te)[:, bi], yf_te, thr_f, benign)
        print(f"full-feature comparison done in {time.time() - t0:.0f}s")

    artifact = export(forest, threshold, metrics, args.out)
    size_mb = os.path.getsize(args.out) / 1e6

    # Parity check: pure-Python inference must reproduce scikit-learn on a sample of test flows.
    model = ForestModel(artifact)
    rng = np.random.default_rng(SEED)
    idx = rng.choice(len(y_te), size=min(2000, len(y_te)), replace=False)
    max_diff = max(abs(model.predict_proba(X_te[i].astype(float).tolist())[benign] - (1 - te_score[i])) for i in idx)
    metrics["parity_max_abs_diff"] = float(max_diff)
    print(f"exported {args.out} ({size_mb:.1f} MB); python-vs-sklearn max |diff| = {max_diff:.2e}")

    with open(args.out.replace(".json.gz", ".metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(json.dumps({k: metrics[k] for k in ("threshold", "test_binary", "test_binary_without_iat", "test_binary_at_validation_fpr")}, indent=2))
    print(json.dumps(per_class, indent=2))
    if "comparison_all_78_features" in metrics:
        print("all-78-features:", json.dumps(metrics["comparison_all_78_features"]))

    write_baseline(X_tr_orig, y_tr_orig, args.out.replace("flow_classifier.json.gz", "baseline.json")
                   if args.out.endswith("flow_classifier.json.gz") else args.out + ".baseline.json")
    if args.test_sample:
        write_test_sample(args.csv_dir, X_te, y_te, args.test_sample, rng)


def write_baseline(X_tr, y_tr, out_path):
    """Baseline profile (for --baseline) from BENIGN training flows only.

    mean/std drive the z-score anomaly check; min/max are the 0.5th/99.5th percentiles so a few
    huge flows do not squash everything else into the bottom of the normalization range.
    """
    benign = X_tr[y_tr == CLASSES.index("BENIGN")]
    profile = {}
    for name in ("duration", "bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "iat_mean", "iat_std"):
        col = benign[:, FEATURE_NAMES.index(name)].astype(np.float64)
        col = col[col != -1.0]
        if col.size == 0:  # e.g. IAT fields when training on Zeek conn.log, which has none
            continue
        profile[name] = {
            "mean": float(col.mean()), "std": float(col.std()) or 1.0,
            "min": float(np.percentile(col, 0.5)), "max": float(np.percentile(col, 99.5)),
        }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)
    print(f"wrote baseline from {len(benign)} benign training flows -> {out_path}")


def write_test_sample(csv_dir, X_te, y_te, out_path, rng, per_class=300, benign_n=3000):
    """Stratified sample of test flows as pipeline JSONL (features map 1:1 back to flow fields)."""
    benign = CLASSES.index("BENIGN")
    picks = []
    for c in np.unique(y_te):
        idx = np.where(y_te == c)[0]
        n = benign_n if c == benign else per_class
        picks.extend(rng.choice(idx, size=min(n, len(idx)), replace=False).tolist())
    rng.shuffle(picks)
    raw = ["dst_port", "duration", "packets_sent", "packets_recv", "bytes_sent", "bytes_recv", "iat_mean", "iat_std"]
    with open(out_path, "w", encoding="utf-8") as f:
        for n, i in enumerate(picks):
            label = CLASSES[int(y_te[i])]
            category, subtype = LABEL_MAP[label]
            flow = {"flow_id": f"cic-test-{n}", "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0", "src_port": 0,
                    "protocol": "UNKNOWN", "label": "BENIGN" if label == "BENIGN" else "ATTACK",
                    "cic_label": label, "category": category, "subtype": subtype}
            for k, v in zip(raw, X_te[i].tolist()):
                flow[k] = None if v == -1.0 else (int(v) if k == "dst_port" else v)
            f.write(json.dumps(flow) + "\n")
    print(f"wrote {len(picks)} test flows -> {out_path}")


if __name__ == "__main__":
    main()
