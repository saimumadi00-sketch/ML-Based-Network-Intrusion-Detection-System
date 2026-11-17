"""Pure-Python inference for the random-forest flow classifier exported by scripts/train_model.py.

The artifact is gzipped JSON (no pickle, so loading it cannot execute code). Features are rounded
to float32 before comparison, exactly as scikit-learn does, so predictions match the trained model.
"""
from __future__ import annotations

import gzip
import json
import os
import struct
from typing import Any, Dict, List, Tuple

from .features import FEATURE_NAMES, flow_features

_F32 = struct.Struct("f")
_CACHE: Dict[str, Tuple[float, "ForestModel"]] = {}


def _f32(x: float) -> float:
    return _F32.unpack(_F32.pack(x))[0]


class ForestModel:
    def __init__(self, artifact: Dict[str, Any]) -> None:
        if artifact.get("type") != "random_forest":
            raise ValueError(f"unsupported model type: {artifact.get('type')!r}")
        if artifact["feature_names"] != FEATURE_NAMES:
            raise ValueError("model was trained with a different feature set; retrain it")
        self.version: str = artifact.get("version", "unknown")
        self.classes: List[str] = artifact["classes"]
        self.class_map: Dict[str, List[str]] = artifact["class_map"]
        self.threshold: float = float(artifact["threshold"])
        self.benign_idx = self.classes.index("BENIGN")
        self.trees = artifact["trees"]
        self.metrics = artifact.get("metrics", {})

    @classmethod
    def load(cls, path: str) -> "ForestModel":
        mtime = os.path.getmtime(path)
        cached = _CACHE.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as f:
            model = cls(json.load(f))
        _CACHE[path] = (mtime, model)
        return model

    def predict_proba(self, features: List[float]) -> List[float]:
        x = [_f32(v) for v in features]
        n = len(self.classes)
        totals = [0.0] * n
        for tree in self.trees:
            feat, thr, left, right, leaf = tree["f"], tree["t"], tree["l"], tree["r"], tree["v"]
            node = 0
            while left[node] != -1:
                node = left[node] if x[feat[node]] <= thr[node] else right[node]
            for cls_idx, p in leaf[str(node)]:
                totals[cls_idx] += p
        k = float(len(self.trees))
        return [t / k for t in totals]

    def predict(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        proba = self.predict_proba(flow_features(flow))
        attack_score = 1.0 - proba[self.benign_idx]
        out: Dict[str, Any] = {"attack_score": round(attack_score, 4), "model_version": self.version}
        if attack_score < self.threshold:
            out.update({
                "label": "BENIGN", "category": "BENIGN", "subtype": "N/A",
                "confidence": round(proba[self.benign_idx], 4),
            })
            return out
        # Attack: pick the most likely attack class; category/subtype confidences are relative to the attack mass.
        attack = [(p, c) for c, p in enumerate(proba) if c != self.benign_idx]
        top_p, top_c = max(attack)
        label = self.classes[top_c]
        category, subtype = self.class_map[label]
        cat_mass = sum(p for p, c in attack if self.class_map[self.classes[c]][0] == category)
        out.update({
            "label": label,
            "category": category,
            "subtype": subtype,
            "confidence": round(attack_score, 4),
            "category_confidence": round(cat_mass / attack_score, 4) if attack_score else 0.0,
            "subtype_confidence": round(top_p / attack_score, 4) if attack_score else 0.0,
        })
        return out
