"""
run_rlm_contractnli.py
ContractNLI evaluation using the RLM-specialized model
(mit-oasys/rlm-qwen3-8b-v0.1) served via vLLM, driven by the AUTHORS' `rlm`
library scaffold (NOT dspy.RLM). This matters: the checkpoint was post-trained
on trajectories from this exact scaffold, so it expects the rlm library's
system prompt and REPL protocol.

Pipeline:
  vLLM server (serve_rlm_qwen3.sh)  <--OpenAI API-->  rlm.RLM client

Install:
    pip install rlms scikit-learn

Run the server first (serve_rlm_qwen3.sh), then:
    python run_rlm_contractnli.py --split dev --limit 5
"""

import os
import re
import json
import time
import argparse
from collections import defaultdict

from sklearn.metrics import balanced_accuracy_score, f1_score, classification_report

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
DATA_DIR = r"C:\Users\Computec\Downloads\contract-nli (1)\contract-nli"
LABELS = ["Entailment", "Contradiction", "NotMentioned"]

# Point at your vLLM server. On the same box this is localhost; from your
# laptop to a RunPod box use the pod's public URL / forwarded port.
VLLM_BASE_URL = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
VLLM_API_KEY = os.environ.get("VLLM_API_KEY", "EMPTY")  # vLLM ignores the key
SERVED_MODEL = os.environ.get("VLLM_MODEL", "rlm-qwen3-8b")

MODE_NAME = "rlm_specialized"   # output folder name


# ----------------------------------------------------------------------
# Data loading  (same structure as the main script)
# ----------------------------------------------------------------------
def load_split(split):
    with open(os.path.join(DATA_DIR, f"{split}.json"), encoding="utf-8") as f:
        return json.load(f)


def iter_instances(data):
    labels = data["labels"]
    for doc in data["documents"]:
        text = doc["text"]
        annotations = doc["annotation_sets"][0]["annotations"]
        for nda_key, ann in annotations.items():
            yield (doc["id"], nda_key,
                   labels[nda_key]["hypothesis"], text, ann["choice"])


def normalize_label(raw):
    if raw is None:
        return "NotMentioned"
    if "</think>" in raw:
        raw = raw.split("</think>")[-1]
    s = re.sub(r"[`'\"*]", "", raw.strip().lower())
    if "contradict" in s:
        return "Contradiction"
    if "entail" in s:
        return "Entailment"
    if "not mentioned" in s or "notmentioned" in s or "neutral" in s:
        return "NotMentioned"
    return "NotMentioned"


# ----------------------------------------------------------------------
# RLM client (authors' library) pointed at vLLM
# ----------------------------------------------------------------------
def build_rlm():
    from rlm import RLM

    # The rlm library talks to local vLLM through its OpenAI-compatible client.
    rlm = RLM(
        backend="openai",
        backend_kwargs={
            "model_name": SERVED_MODEL,
            "base_url": VLLM_BASE_URL,
            "api_key": VLLM_API_KEY,
        },
        environment="local",   # REPL runs in this process; fine for benchmarking
        verbose=False,
    )
    return rlm


PROMPT = (
    "You are given a non-disclosure agreement (NDA) as the context variable. "
    "Decide the relationship between the contract and this hypothesis, and "
    "answer with exactly one label: Entailment, Contradiction, or NotMentioned.\n"
    "Hypothesis: {hypothesis}"
)


def predict_rlm(rlm, hypothesis, contract):
    """One RLM completion. The contract is passed as the offloaded context."""
    prompt = PROMPT.format(hypothesis=hypothesis)
    # rlm.completion(prompt, context=...) offloads `context` into the REPL.
    result = rlm.completion(prompt, context=contract)
    text = getattr(result, "response", None) or str(result)

    # Token usage: the rlm library exposes aggregate usage on the result
    # metadata when a logger is attached; we read best-effort fields here.
    usage = {"prompt": 0, "completion": 0, "reasoning": 0, "total": 0}
    try:
        meta = getattr(result, "metadata", None)
        if meta and isinstance(meta, dict):
            u = meta.get("usage") or {}
            usage["prompt"] = u.get("prompt_tokens", 0) or 0
            usage["completion"] = u.get("completion_tokens", 0) or 0
            usage["total"] = u.get("total_tokens", 0) or (
                usage["prompt"] + usage["completion"])
    except Exception:
        pass

    return normalize_label(text), usage


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------
def _out_dir():
    path = os.path.join(DATA_DIR, "results", MODE_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def evaluate(split, limit=None):
    data = load_split(split)
    instances = list(iter_instances(data))
    if limit:
        instances = instances[:limit]

    rlm = build_rlm()

    y_true, y_pred, usage_records = [], [], []
    per_hyp = defaultdict(lambda: {"true": [], "pred": []})
    n_errors = 0

    for i, (doc_id, nda_key, hyp, contract, gold) in enumerate(instances, 1):
        try:
            pred, usage = predict_rlm(rlm, hyp, contract)
        except Exception as e:
            print(f"  [error doc {doc_id} {nda_key}]: {e}")
            n_errors += 1
            continue
        y_true.append(gold)
        y_pred.append(pred)
        usage_records.append(usage)
        per_hyp[nda_key]["true"].append(gold)
        per_hyp[nda_key]["pred"].append(pred)
        print(f"  {i}/{len(instances)}  {nda_key}: {pred} (gold {gold})")

    # ---- report ----
    lines = []
    lines.append("=" * 60)
    lines.append("ContractNLI — RLM-specialized model (rlm-qwen3-8b-v0.1)")
    lines.append("=" * 60)
    lines.append(f"Timestamp : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Model     : {SERVED_MODEL} via {VLLM_BASE_URL}")
    lines.append(f"Split     : {split} | Limit: {limit}")
    lines.append(f"Scored    : {len(y_true)} | Errored: {n_errors}")

    if y_true:
        bal = balanced_accuracy_score(y_true, y_pred)
        mf1 = f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)
        lines.append("")
        lines.append(f"Balanced accuracy : {bal:.4f}")
        lines.append(f"Macro F1          : {mf1:.4f}")
        for lab, f in zip(LABELS, f1_score(y_true, y_pred, labels=LABELS,
                                           average=None, zero_division=0)):
            lines.append(f"  F1 [{lab:13}]: {f:.4f}")
        lines.append("")
        lines.append(classification_report(y_true, y_pred, labels=LABELS,
                                            zero_division=0))
        n = len(usage_records)
        if n:
            lines.append("-" * 60)
            lines.append("Efficiency (avg tokens per instance, full RLM tree)")
            lines.append("-" * 60)
            lines.append(f"  Avg prompt     : {sum(u['prompt'] for u in usage_records)/n:.1f}")
            lines.append(f"  Avg completion : {sum(u['completion'] for u in usage_records)/n:.1f}")
            lines.append(f"  Avg total      : {sum(u['total'] for u in usage_records)/n:.1f}")
    else:
        lines.append("No successful predictions.")

    report = "\n".join(lines)
    print("\n" + report)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    out = _out_dir()
    with open(os.path.join(out, f"results_{MODE_NAME}_{split}_{stamp}.txt"),
              "w", encoding="utf-8") as f:
        f.write(report)
    with open(os.path.join(out, f"preds_{MODE_NAME}_{split}.json"),
              "w", encoding="utf-8") as f:
        json.dump([{"true": t, "pred": p, "usage": u}
                   for t, p, u in zip(y_true, y_pred, usage_records)], f, indent=2)
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["train", "dev", "test"], default="dev")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    evaluate(args.split, args.limit)