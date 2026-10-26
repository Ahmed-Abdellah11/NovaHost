"""Model loading + scoring + verdict logic (no I/O side effects)."""
from __future__ import annotations

import joblib
import numpy as np

from . import config
from .features import explain, extract_many, is_valid, normalize


def score_domains(bundle: dict, domains) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (ensemble, gradient-boosting, char-ngram-logreg) maliciousness probabilities."""
    doms = [normalize(d) for d in domains]
    p_gb = bundle["gb"].predict_proba(extract_many(doms))[:, 1]
    p_lr = bundle["lr"].predict_proba(bundle["tfidf"].transform(doms))[:, 1]
    w = bundle["weight_gb"]
    return w * p_gb + (1 - w) * p_lr, p_gb, p_lr


class Classifier:
    def __init__(self, path=config.MODEL_PATH):
        self.bundle = joblib.load(path)
        self.block_t = config.BLOCK_T if config.BLOCK_T is not None else self.bundle["block_t"]
        self.suspect_t = config.SUSPECT_T if config.SUSPECT_T is not None else self.bundle["suspect_t"]

    @property
    def version(self) -> str:
        return self.bundle.get("version", "unknown")

    def verdict(self, score: float) -> str:
        if score >= self.block_t:
            return "BLOCK"
        if score >= self.suspect_t:
            return "SUSPICIOUS"
        return "SAFE"

    def classify(self, domain: str) -> dict:
        d = normalize(domain)
        if not is_valid(d):
            raise ValueError(f"not a valid domain: {domain!r}")
        s = float(score_domains(self.bundle, [d])[0][0])
        v = self.verdict(s)
        return {"domain": d, "verdict": v, "score": round(s, 4),
                "reasons": explain(d) if v != "SAFE" else []}

    def classify_many(self, domains) -> list[dict]:
        doms = [normalize(d) for d in domains]
        scores = score_domains(self.bundle, doms)[0]
        out = []
        for d, s in zip(doms, scores):
            v = self.verdict(float(s))
            out.append({"domain": d, "verdict": v, "score": round(float(s), 4),
                        "reasons": explain(d) if v != "SAFE" else []})
        return out
