"""Train + evaluate the model.   python -m nova.train

Pipeline
  1. group-aware split by registered domain (70 / 10 / 20) so the same site never leaks
     between train and test
  2. model A: HistGradientBoosting on 20 hand-crafted lexical features
     model B: logistic regression on TF-IDF character n-grams (2-4)
  3. ensemble weight + decision thresholds chosen on the VALIDATION set only
     (block threshold = 0.5 % false-positive rate, suspicious threshold = 3 %)
  4. final numbers + plots are computed on the untouched TEST set
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit

from .config import MODEL_PATH, ROOT
from .features import FEATURE_NAMES, extract_many, normalize
from .predict import score_domains

REPORTS = ROOT / "reports"
SEED = 42


def split(df):
    g1 = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=SEED)
    tv_i, te_i = next(g1.split(df, df["label"], df["group"]))
    tv, te = df.iloc[tv_i], df.iloc[te_i]
    g2 = GroupShuffleSplit(n_splits=1, test_size=0.125, random_state=SEED)
    tr_i, va_i = next(g2.split(tv, tv["label"], tv["group"]))
    return tv.iloc[tr_i], tv.iloc[va_i], te


def at_threshold(y, s, t):
    pred = (s >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {"threshold": round(float(t), 4), "accuracy": accuracy_score(y, pred),
            "precision": precision_score(y, pred), "recall": recall_score(y, pred),
            "f1": f1_score(y, pred), "false_positive_rate": fp / (fp + tn),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def main():
    t0 = time.time()
    df = pd.read_csv(ROOT / "data" / "dataset.csv.gz")
    tr, va, te = split(df)
    print(f"train={len(tr)} val={len(va)} test={len(te)}  (grouped by registered domain)")

    Xtr = extract_many(tr["domain"])
    gb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, max_leaf_nodes=31,
                                        early_stopping=True, random_state=SEED).fit(Xtr, tr["label"])
    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=5,
                            max_features=300_000, sublinear_tf=True)
    lr = LogisticRegression(C=4, solver="liblinear", max_iter=300).fit(
        tfidf.fit_transform([normalize(d) for d in tr["domain"]]), tr["label"])
    bundle = {"gb": gb, "tfidf": tfidf, "lr": lr, "weight_gb": 0.5}

    # ---- choose ensemble weight + thresholds on validation only
    yv = va["label"].to_numpy()
    _, pg, pl = score_domains(bundle, va["domain"])
    best_w = max([0, .25, .5, .75, 1], key=lambda w: roc_auc_score(yv, w * pg + (1 - w) * pl))
    bundle["weight_gb"] = best_w
    sv = best_w * pg + (1 - best_w) * pl
    benign_scores = sv[yv == 0]
    block_t = max(0.5, float(np.quantile(benign_scores, 0.995)))
    suspect_t = min(block_t, max(0.2, float(np.quantile(benign_scores, 0.97))))
    bundle.update(block_t=block_t, suspect_t=suspect_t,
                  version=time.strftime("%Y.%m.%d"), feature_names=FEATURE_NAMES)

    # ---- final evaluation on TEST
    yt = te["label"].to_numpy()
    st, pgt, plt_ = score_domains(bundle, te["domain"])
    metrics = {
        "rows": {"train": len(tr), "val": len(va), "test": len(te)},
        "ensemble_weight_gb": best_w,
        "auc": {"ensemble": roc_auc_score(yt, st), "gradient_boosting": roc_auc_score(yt, pgt),
                "char_ngram_logreg": roc_auc_score(yt, plt_)},
        "at_block_threshold": at_threshold(yt, st, block_t),
        "at_suspicious_threshold": at_threshold(yt, st, suspect_t),
        "recall_by_source_at_block": {
            src: float((st[(te["source"] == src).to_numpy()] >= block_t).mean())
            for src in ["phishing", "hosts"]},
    }
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "metrics.json").write_text(json.dumps(metrics, indent=2))
    joblib.dump(bundle, MODEL_PATH, compress=3)

    # ---- plots
    plt.figure(figsize=(5.5, 5))
    for name, s in [("Ensemble", st), ("Gradient boosting", pgt), ("Char n-gram LR", plt_)]:
        fpr, tpr, _ = roc_curve(yt, s)
        plt.plot(fpr, tpr, label=f"{name} (AUC {roc_auc_score(yt, s):.4f})")
    plt.plot([0, 1], [0, 1], "k--", lw=.7)
    plt.xlabel("False positive rate"); plt.ylabel("True positive rate")
    plt.title("ROC curve (test set)"); plt.legend(loc="lower right"); plt.grid(alpha=.3)
    plt.tight_layout(); plt.savefig(REPORTS / "roc_curve.png", dpi=150); plt.close()

    m = metrics["at_block_threshold"]
    cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
    plt.figure(figsize=(4.8, 4.2)); plt.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            plt.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=13)
    plt.xticks([0, 1], ["Safe", "Block"]); plt.yticks([0, 1], ["Safe", "Malicious"])
    plt.xlabel("Predicted"); plt.ylabel("Actual")
    plt.title(f"Confusion matrix @ threshold {block_t:.2f}")
    plt.tight_layout(); plt.savefig(REPORTS / "confusion_matrix.png", dpi=150); plt.close()

    plt.figure(figsize=(6, 4))
    plt.hist(st[yt == 0], bins=40, alpha=.7, label="Benign", color="#2a9d8f")
    plt.hist(st[yt == 1], bins=40, alpha=.7, label="Malicious", color="#e76f51")
    plt.axvline(suspect_t, color="orange", ls="--", label="suspicious threshold")
    plt.axvline(block_t, color="red", ls="--", label="block threshold")
    plt.yscale("log"); plt.xlabel("Model score"); plt.ylabel("Domains (log)")
    plt.title("Score distribution (test set)"); plt.legend()
    plt.tight_layout(); plt.savefig(REPORTS / "score_distribution.png", dpi=150); plt.close()

    sub = np.random.RandomState(SEED).choice(len(te), 4000, replace=False)
    imp = permutation_importance(gb, extract_many(te["domain"].iloc[sub]), yt[sub],
                                 scoring="roc_auc", n_repeats=3, random_state=SEED)
    order = np.argsort(imp.importances_mean)
    plt.figure(figsize=(6, 5.5))
    plt.barh(np.array(FEATURE_NAMES)[order], imp.importances_mean[order], color="#264653")
    plt.xlabel("AUC drop when feature is shuffled"); plt.title("Feature importance")
    plt.tight_layout(); plt.savefig(REPORTS / "feature_importance.png", dpi=150); plt.close()

    print(json.dumps(metrics, indent=2))
    print(f"[+] model -> {MODEL_PATH} ({MODEL_PATH.stat().st_size/1e6:.1f} MB) in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
