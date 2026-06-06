"""
ContractNLI zero-shot evaluation on Qwen3-8B via OpenRouter.

Two paths:
  1. Raw OpenRouter chat-completions call  (--mode raw)
  2. DSPy-orchestrated call                (--mode dspy)

Reports balanced accuracy + macro F1 (and per-class F1) against the
gold annotations.

SECURITY: set your key in the environment, do NOT hardcode it.
    Windows (PowerShell):  $env:OPENROUTER_API_KEY="sk-or-v1-..."
    Linux/Mac:             export OPENROUTER_API_KEY="sk-or-v1-..."
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
MODEL = "qwen/qwen3-8b"          # OpenRouter model slug
LABELS = ["Entailment", "Contradiction", "NotMentioned"]

# NOTE: this key is visible in your chat history. Rotate it on OpenRouter
# after you're done and treat this one as compromised.
API_KEY = os.environ.get("OPENROUTER_API_KEY")

# Path to your split files
DATA_DIR = r"C:\Users\Computec\Downloads\contract-nli (1)\contract-nli"

# Long-context study: pass the full contract text, no truncation.
MAX_CHARS = None

# Local tokenizer used ONLY to count tokens inside <think>...</think> blocks,
# as a provider-independent measure of how much the model actually reasoned.
# (cl100k_base is a reasonable proxy; it won't exactly match Qwen's tokenizer
#  but is consistent across all conditions, which is what matters for comparison.)
try:
    import tiktoken
    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:
    _ENC = None

_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)


def count_think_tokens(raw_text):
    """Count tokens inside <think>...</think> blocks of a raw model output.

    Returns 0 if there is no think block. Run on EVERY condition so we can
    detect a provider doing hidden reasoning even when thinking was 'off'.
    """
    if not raw_text:
        return 0
    blocks = _THINK_RE.findall(raw_text)
    if not blocks:
        return 0
    joined = "\n".join(blocks)
    if _ENC is not None:
        return len(_ENC.encode(joined))
    # fallback: rough word-count estimate if tiktoken unavailable
    return len(joined.split())



# ----------------------------------------------------------------------
# Data loading
# ----------------------------------------------------------------------
def load_split(split):
    path = os.path.join(DATA_DIR, f"{split}.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def iter_instances(data, max_chars=MAX_CHARS):
    """Yield (doc_id, nda_key, hypothesis, contract_text, gold_choice)."""
    labels = data["labels"]
    for doc in data["documents"]:
        text = doc["text"]
        if max_chars:
            text = text[:max_chars]
        annotations = doc["annotation_sets"][0]["annotations"]
        for nda_key, ann in annotations.items():
            yield (
                doc["id"],
                nda_key,
                labels[nda_key]["hypothesis"],
                text,
                ann["choice"],
            )


# ----------------------------------------------------------------------
# Label parsing
# ----------------------------------------------------------------------
def normalize_label(raw):
    """Map a free-form model answer to one of the three canonical labels."""
    if raw is None:
        return "NotMentioned"
    # Qwen3 may emit a <think>...</think> block before the answer; drop it
    # and keep what comes after the final closing tag.
    if "</think>" in raw:
        raw = raw.split("</think>")[-1]
    s = raw.strip().lower()
    # strip code fences / quotes / punctuation
    s = re.sub(r"[`'\"*]", "", s)
    if "contradict" in s:
        return "Contradiction"
    if "entail" in s:
        return "Entailment"
    if "not mentioned" in s or "notmentioned" in s or "neutral" in s:
        return "NotMentioned"
    # fallback
    return "NotMentioned"


def _get(obj, key, default=0):
    """Read key from a dict OR an attribute from an object."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _extract_usage(usage):
    """Normalize an OpenRouter/LiteLLM usage dict/object to a flat token record.

    Handles both plain dicts and LiteLLM wrapper objects (Usage,
    CompletionTokensDetailsWrapper). completion_tokens already INCLUDES
    reasoning tokens for thinking models; the reasoning portion is also
    exposed separately under completion_tokens_details.reasoning_tokens.
    """
    if not usage:
        return {"prompt": 0, "completion": 0, "reasoning": 0,
                "total": 0, "think_tokens": 0}
    prompt = _get(usage, "prompt_tokens", 0) or 0
    completion = _get(usage, "completion_tokens", 0) or 0
    total = _get(usage, "total_tokens", 0) or (prompt + completion)
    reasoning = 0
    details = _get(usage, "completion_tokens_details", None)
    if details is not None:
        reasoning = _get(details, "reasoning_tokens", 0) or 0
    return {
        "prompt": prompt,
        "completion": completion,
        "reasoning": reasoning,
        "total": total,
        "think_tokens": 0,  # filled in by caller via count_think_tokens()
    }


PROMPT_TEMPLATE = """You are analyzing a non-disclosure agreement (NDA).

Decide the relationship between the CONTRACT and the HYPOTHESIS. Answer with exactly one of these three labels and nothing else:
- Entailment   (the contract supports / implies the hypothesis)
- Contradiction (the contract states the opposite of the hypothesis)
- NotMentioned (the contract does not address the hypothesis)

CONTRACT:
{contract}

HYPOTHESIS:
{hypothesis}

Answer (one label only): /no_think"""


# ----------------------------------------------------------------------
# Path 1: raw OpenRouter
# ----------------------------------------------------------------------
def predict_raw(hypothesis, contract):
    import requests

    prompt = PROMPT_TEMPLATE.format(contract=contract, hypothesis=hypothesis)
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        data=json.dumps({
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            # Zero-shot / instruct-style: no chain-of-thought reasoning.
            "reasoning": {"enabled": False},
            # Ask OpenRouter to include token accounting in the response.
            "usage": {"include": True},
        }),
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    usage = _extract_usage(data.get("usage", {}) or {})
    # Provider-independent reasoning measure: count tokens inside <think>.
    # If the provider reported reasoning_tokens, keep the larger of the two.
    think_tok = count_think_tokens(content)
    usage["think_tokens"] = think_tok
    if usage["reasoning"] == 0 and think_tok > 0:
        usage["reasoning"] = think_tok
    return normalize_label(content), usage


# ----------------------------------------------------------------------
# Path 2: DSPy
# ----------------------------------------------------------------------
def build_dspy_program(condition="zeroshot"):
    """
    condition:
      "zeroshot"  -> Predict,         thinking OFF  (neither mechanism)
      "cot"       -> ChainOfThought,  thinking OFF  (prompt CoT only)
      "reasoning" -> Predict,         thinking ON   (native reasoning only)
      "cot_think" -> ChainOfThought,  thinking ON   (prompt CoT + native)
    """
    import dspy

    # Native model thinking is ON for "reasoning" and "cot_think".
    #   - reasoning  : native thinking only (Predict)
    #   - cot_think  : native thinking + prompt-elicited CoT (ChainOfThought)
    #   - cot        : prompt-elicited CoT only, native thinking OFF
    #   - zeroshot   : neither
    thinking_on = condition in ("reasoning", "cot_think")

    lm = dspy.LM(
        f"openrouter/{MODEL}",
        api_key=API_KEY,
        api_base="https://openrouter.ai/api/v1",
        temperature=0.0,
        reasoning={"enabled": thinking_on},
        # Ask OpenRouter to include the usage block in the response.
        extra_body={"usage": {"include": True}},
        # Disable caching: cached responses don't carry usage metadata, which
        # is why tokens vanish on repeated identical runs. We need a live call
        # each time to get accurate token accounting.
        cache=False,
    )
    # track_usage=True lets us read per-call tokens via out.get_lm_usage().
    dspy.configure(lm=lm, track_usage=True)

    class ContractNLI(dspy.Signature):
        """Classify the relationship between an NDA contract and a hypothesis.
        Answer with exactly one of: Entailment, Contradiction, NotMentioned."""

        contract: str = dspy.InputField(desc="full text of the NDA")
        hypothesis: str = dspy.InputField(desc="statement to verify against the contract")
        label: str = dspy.OutputField(desc="one of: Entailment, Contradiction, NotMentioned")

    if condition in ("cot", "cot_think"):
        # ChainOfThought adds a rationale field before the label (prompt CoT).
        # For cot_think, native thinking is additionally ON (set above).
        return dspy.ChainOfThought(ContractNLI)

    # zeroshot and reasoning both use Predict (direct label).
    # The difference between them is native thinking on/off, set above.
    return dspy.Predict(ContractNLI)


# ----------------------------------------------------------------------
# Path 3: RLM (Recursive Language Model) — coding-agent strategy.
# RLM stores the contract as a variable in a sandboxed Python REPL and lets
# the model explore it with code + recursive sub-LLM calls, instead of
# stuffing the whole contract into the prompt. This is the long-context /
# context-rot mitigation condition from the proposal (Strategy 4).
#
# Requires Deno installed for the Pyodide WASM sandbox:
#   curl -fsSL https://deno.land/install.sh | sh   (then restart shell)
# On Windows:  irm https://deno.land/install.ps1 | iex
# ----------------------------------------------------------------------
def build_rlm_program(thinking_on=False, max_iterations=10, max_llm_calls=20):
    import dspy

    lm = dspy.LM(
        f"openrouter/{MODEL}",
        api_key=API_KEY,
        api_base="https://openrouter.ai/api/v1",
        temperature=0.0,
        reasoning={"enabled": thinking_on},
        extra_body={"usage": {"include": True}},
        cache=False,
    )
    dspy.configure(lm=lm, track_usage=True)

    # RLM uses a string signature. We give it the contract + hypothesis and ask
    # for a single label. The root LM writes Python to explore `contract` and
    # may spawn sub-LLM calls (which reuse the same lm via dspy.settings.lm).
    rlm = dspy.RLM(
        "contract, hypothesis -> label",
        max_iterations=max_iterations,
        max_llm_calls=max_llm_calls,
        verbose=False,
    )
    return rlm


def predict_rlm(program, hypothesis, contract):
    import dspy

    instruction = (
        "Decide the relationship between the contract and the hypothesis. "
        "Return exactly one label: Entailment, Contradiction, or NotMentioned. "
        f"Hypothesis: {hypothesis}"
    )
    out = program(contract=contract, hypothesis=instruction)

    # Usage: RLM aggregates all root + sub-LLM calls via get_lm_usage().
    usage = {"prompt": 0, "completion": 0, "reasoning": 0,
             "total": 0, "think_tokens": 0}
    try:
        lm_usage = out.get_lm_usage() or {}
        acc = {"prompt": 0, "completion": 0, "reasoning": 0, "total": 0}
        any_model = False
        for _model, u in lm_usage.items():
            any_model = True
            e = _extract_usage(u)
            acc["prompt"] += e["prompt"]
            acc["completion"] += e["completion"]
            acc["reasoning"] += e["reasoning"]
            acc["total"] += e["total"]
        if any_model:
            acc["think_tokens"] = 0
            usage = acc
    except Exception:
        pass

    # RLM returns the answer under the signature's output field name ("label").
    label_raw = getattr(out, "label", None)
    return normalize_label(label_raw), usage


def _raw_output_from_history(lm):
    """Best-effort extraction of the raw model completion text from DSPy history,
    so we can scan for <think> blocks regardless of how DSPy parsed the fields."""
    try:
        if not lm or not lm.history:
            return ""
        entry = lm.history[-1]
        # DSPy stores the raw provider response under "response"; the text may
        # also be available under "outputs".
        outputs = entry.get("outputs")
        if outputs:
            if isinstance(outputs, list):
                return "\n".join(str(o) for o in outputs)
            return str(outputs)
        resp = entry.get("response")
        if resp is not None:
            # LiteLLM ModelResponse-like object
            try:
                return resp.choices[0].message.content or ""
            except Exception:
                return str(resp)
    except Exception:
        pass
    return ""


def _usage_from_history(lm):
    """Pull a usage dict from the most recent DSPy history entry.
    Used as a fallback when out.get_lm_usage() returns empty."""
    try:
        if not lm or not lm.history:
            return {}
        entry = lm.history[-1]
        # usage may be a top-level key, or nested in the response object
        u = entry.get("usage")
        if u:
            return u if isinstance(u, dict) else dict(u)
        resp = entry.get("response")
        if resp is not None:
            ru = getattr(resp, "usage", None)
            if ru is not None:
                # LiteLLM Usage object -> dict
                try:
                    return dict(ru)
                except Exception:
                    return {
                        "prompt_tokens": getattr(ru, "prompt_tokens", 0),
                        "completion_tokens": getattr(ru, "completion_tokens", 0),
                        "total_tokens": getattr(ru, "total_tokens", 0),
                        "completion_tokens_details":
                            getattr(ru, "completion_tokens_details", None),
                    }
    except Exception:
        pass
    return {}


def _usage_is_empty(u):
    return (u.get("prompt", 0) == 0
            and u.get("completion", 0) == 0
            and u.get("total", 0) == 0)


def predict_dspy(program, hypothesis, contract):
    import dspy

    out = program(contract=contract, hypothesis=hypothesis)

    # Source 1: official DSPy usage tracking (track_usage=True).
    # Structure is {model_name: usage_dict}. Sum across models (usually one),
    # passing each model's usage dict straight to _extract_usage so the
    # nested completion_tokens_details object is handled correctly.
    usage = {"prompt": 0, "completion": 0, "reasoning": 0,
             "total": 0, "think_tokens": 0}
    try:
        lm_usage = out.get_lm_usage() or {}
        acc = {"prompt": 0, "completion": 0, "reasoning": 0, "total": 0}
        any_model = False
        for _model, u in lm_usage.items():
            any_model = True
            e = _extract_usage(u)
            acc["prompt"] += e["prompt"]
            acc["completion"] += e["completion"]
            acc["reasoning"] += e["reasoning"]
            acc["total"] += e["total"]
        if any_model:
            acc["think_tokens"] = 0
            usage = acc
    except Exception:
        pass

    # Source 2 (fallback): read straight from lm.history if Source 1 was empty.
    if _usage_is_empty(usage):
        hist_usage = _usage_from_history(dspy.settings.lm)
        if hist_usage:
            usage = _extract_usage(hist_usage)

    # Provider-independent reasoning measure from the raw <think> block.
    raw_text = _raw_output_from_history(dspy.settings.lm)
    think_tok = count_think_tokens(raw_text)
    usage["think_tokens"] = think_tok
    if usage["reasoning"] == 0 and think_tok > 0:
        usage["reasoning"] = think_tok

    return normalize_label(out.label), usage


# ----------------------------------------------------------------------
# Output organization: each mode writes into results/<folder>/
# ----------------------------------------------------------------------
MODE_FOLDER = {
    "raw": "zeroshot-raw",
    "dspy": "zeroshot-dspy",
    "cot": "cot",
    "cot_think": "cot_think",
    "reasoning": "reasoning",
    "rlm": "rlm",
    "rlm_think": "rlm_think",
}


def _mode_dir(mode):
    """results/<mode-folder>/ , created if needed."""
    folder = MODE_FOLDER.get(mode, mode)
    path = os.path.join(DATA_DIR, "results", folder)
    os.makedirs(path, exist_ok=True)
    return path


# ----------------------------------------------------------------------
# Evaluation
def _write_report(mode, split, report):
    """Write the metrics report to a timestamped text file in the mode folder."""
    stamp = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(_mode_dir(mode), f"results_{mode}_{split}_{stamp}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nResults saved to {path}")


# ----------------------------------------------------------------------
def evaluate(mode, split, limit=None):
    if not API_KEY:
        raise SystemExit("Set OPENROUTER_API_KEY in your environment first.")

    data = load_split(split)
    instances = list(iter_instances(data))
    if limit:
        instances = instances[:limit]

    if mode == "raw":
        program = None
    elif mode == "dspy":
        program = build_dspy_program(condition="zeroshot")
    elif mode == "cot":
        program = build_dspy_program(condition="cot")
    elif mode == "reasoning":
        program = build_dspy_program(condition="reasoning")
    elif mode == "cot_think":
        program = build_dspy_program(condition="cot_think")
    elif mode == "rlm":
        program = build_rlm_program(thinking_on=False)
    elif mode == "rlm_think":
        program = build_rlm_program(thinking_on=True)
    else:
        raise ValueError(f"unknown mode: {mode}")

    y_true, y_pred = [], []
    per_hyp = defaultdict(lambda: {"true": [], "pred": []})
    n_errors = 0
    usage_records = []  # one dict per successful instance

    for i, (doc_id, nda_key, hyp, contract, gold) in enumerate(instances, 1):
        try:
            if mode == "raw":
                pred, usage = predict_raw(hyp, contract)
            elif mode in ("rlm", "rlm_think"):
                pred, usage = predict_rlm(program, hyp, contract)
            else:  # dspy / cot / reasoning / cot_think use the DSPy program
                pred, usage = predict_dspy(program, hyp, contract)
        except Exception as e:
            print(f"  [error doc {doc_id} {nda_key}]: {e}")
            n_errors += 1
            continue  # do NOT score failed calls as a prediction

        y_true.append(gold)
        y_pred.append(pred)
        per_hyp[nda_key]["true"].append(gold)
        per_hyp[nda_key]["pred"].append(pred)
        usage_records.append(usage)

        if i % 25 == 0:
            print(f"  {i}/{len(instances)} done")
        time.sleep(0.2)  # gentle rate limiting

    # ------------------------------------------------------------------
    # Build the report as a string so we can both print and save it.
    # ------------------------------------------------------------------
    lines = []
    lines.append("=" * 60)
    lines.append("ContractNLI zero-shot evaluation")
    lines.append("=" * 60)
    lines.append(f"Timestamp   : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Model       : {MODEL}")
    lines.append(f"Mode        : {mode}")
    lines.append(f"Split       : {split}")
    lines.append(f"Limit       : {limit}")
    lines.append(f"Max chars   : {MAX_CHARS}")
    lines.append(f"Scored      : {len(y_true)} instances")
    lines.append(f"Errored     : {n_errors} (excluded from metrics)")
    if n_errors:
        lines.append("WARNING: some calls failed. Fix these before trusting the metrics.")

    if not y_true:
        lines.append("No successful predictions — nothing to score.")
        report = "\n".join(lines)
        print(report)
        _write_report(mode, split, report)
        return

    bal_acc = balanced_accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)
    f1_per = f1_score(y_true, y_pred, labels=LABELS, average=None, zero_division=0)

    lines.append("")
    lines.append("-" * 60)
    lines.append("Overall metrics")
    lines.append("-" * 60)
    lines.append(f"Balanced accuracy : {bal_acc:.4f}")
    lines.append(f"Macro F1          : {macro_f1:.4f}")
    for lab, f in zip(LABELS, f1_per):
        lines.append(f"  F1 [{lab:13}]: {f:.4f}")

    lines.append("")
    lines.append("Full classification report:")
    lines.append(classification_report(y_true, y_pred, labels=LABELS, zero_division=0))

    # Per-hypothesis breakdown
    lines.append("-" * 60)
    lines.append("Per-hypothesis balanced accuracy")
    lines.append("-" * 60)
    for nda_key in sorted(per_hyp.keys(), key=lambda x: int(x.split("-")[1])):
        t = per_hyp[nda_key]["true"]
        p = per_hyp[nda_key]["pred"]
        try:
            ba = balanced_accuracy_score(t, p)
        except Exception:
            ba = float("nan")
        lines.append(f"  {nda_key:>7} | n={len(t):>3} | bal_acc={ba:.3f}")

    # ------------------------------------------------------------------
    # Efficiency (token usage) — proposal's second evaluation dimension.
    # ------------------------------------------------------------------
    lines.append("")
    lines.append("-" * 60)
    lines.append("Efficiency (tokens per instance, averaged over scored)")
    lines.append("-" * 60)
    n = len(usage_records)
    if n:
        sum_prompt = sum(u["prompt"] for u in usage_records)
        sum_completion = sum(u["completion"] for u in usage_records)
        sum_reasoning = sum(u["reasoning"] for u in usage_records)
        sum_total = sum(u["total"] for u in usage_records)
        lines.append(f"  Avg prompt tokens     : {sum_prompt / n:.1f}")
        lines.append(f"  Avg completion tokens : {sum_completion / n:.1f}")
        lines.append(f"  Avg reasoning tokens  : {sum_reasoning / n:.1f}")
        lines.append(f"  Avg total tokens      : {sum_total / n:.1f}")
        sum_think = sum(u.get("think_tokens", 0) for u in usage_records)
        n_with_think = sum(1 for u in usage_records if u.get("think_tokens", 0) > 0)
        lines.append(f"  Avg <think> tokens    : {sum_think / n:.1f}")
        lines.append(f"  Instances with <think>: {n_with_think}/{n}")
        lines.append("")
        lines.append(f"  Total prompt tokens     : {sum_prompt}")
        lines.append(f"  Total completion tokens : {sum_completion}")
        lines.append(f"  Total reasoning tokens  : {sum_reasoning}")
        lines.append(f"  Total <think> tokens    : {sum_think}")
        lines.append(f"  Total tokens (all calls): {sum_total}")
        if sum_total == 0:
            lines.append("  NOTE: usage came back empty — provider may not report tokens.")
        # 'Reasoning behind our back' check: thinking-off conditions should
        # have zero <think> tokens. cot_think and reasoning have thinking ON,
        # so they are excluded from this check.
        if mode in ("raw", "dspy", "cot") and n_with_think > 0:
            lines.append("")
            lines.append(f"  ** WARNING: thinking was supposed to be OFF for mode "
                         f"'{mode}', but {n_with_think} instances contained a "
                         f"<think> block. The provider may be reasoning anyway. **")
    else:
        lines.append("  No usage records.")

    report = "\n".join(lines)
    print("\n" + report)

    # Save the text report
    _write_report(mode, split, report)

    # Save raw predictions + per-instance usage (JSON) into the mode folder
    preds_path = os.path.join(_mode_dir(mode), f"preds_{mode}_{split}.json")
    with open(preds_path, "w", encoding="utf-8") as f:
        json.dump(
            [{"true": t, "pred": p, "usage": u}
             for t, p, u in zip(y_true, y_pred, usage_records)],
            f, indent=2,
        )
    print(f"Predictions saved to {preds_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",
                    choices=["raw", "dspy", "cot", "reasoning", "cot_think",
                             "rlm", "rlm_think"],
                    default="raw",
                    help="raw=direct OpenRouter instruct; dspy=DSPy zero-shot; "
                         "cot=ChainOfThought (thinking off); "
                         "reasoning=Predict (native thinking on); "
                         "cot_think=ChainOfThought + native thinking on; "
                         "rlm=Recursive LM (REPL exploration, thinking off); "
                         "rlm_think=Recursive LM + native thinking on")
    ap.add_argument("--split", choices=["train", "dev", "test"], default="dev")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap number of instances (for quick smoke tests)")
    args = ap.parse_args()
    evaluate(args.mode, args.split, args.limit)