"""
Standalone probe: make ONE DSPy call and dump everything we can find about
token usage, so we know exactly where (if anywhere) the numbers live.

Run:  python probe_usage.py
"""

import json
import dspy
import os

MODEL = "qwen/qwen3-8b"
API_KEY = os.environ.get("OPENROUTER_API_KEY")

lm = dspy.LM(
    f"openrouter/{MODEL}",
    api_key=API_KEY,
    api_base="https://openrouter.ai/api/v1",
    temperature=0.0,
    reasoning={"enabled": True},
    extra_body={"usage": {"include": True}},
    cache=False,
)
dspy.configure(lm=lm, track_usage=True)


class ContractNLI(dspy.Signature):
    """Classify the relationship between an NDA contract and a hypothesis.
    Answer with exactly one of: Entailment, Contradiction, NotMentioned."""
    contract: str = dspy.InputField()
    hypothesis: str = dspy.InputField()
    label: str = dspy.OutputField(desc="one of: Entailment, Contradiction, NotMentioned")


program = dspy.Predict(ContractNLI)

out = program(
    contract="The Recipient shall use the Confidential Information solely for the "
             "purpose for which it was disclosed.",
    hypothesis="Receiving Party shall not use any Confidential Information for any "
               "purpose other than the purposes stated in Agreement.",
)

print("=" * 70)
print("1) out.get_lm_usage():")
print("=" * 70)
try:
    print(json.dumps(out.get_lm_usage(), indent=2, default=str))
except Exception as e:
    print("ERROR:", e)

print("\n" + "=" * 70)
print("2) dspy.settings.lm.history length:", len(dspy.settings.lm.history))
print("=" * 70)

if dspy.settings.lm.history:
    entry = dspy.settings.lm.history[-1]
    print("History entry KEYS:", list(entry.keys()))
    print()
    # Dump each key shallowly
    for k, v in entry.items():
        preview = str(v)
        if len(preview) > 500:
            preview = preview[:500] + " ...[truncated]"
        print(f"--- {k} ---")
        print(preview)
        print()

    # Specifically look for usage
    print("=" * 70)
    print("3) entry.get('usage'):")
    print("=" * 70)
    print(json.dumps(entry.get("usage"), indent=2, default=str))

    print("\n" + "=" * 70)
    print("4) entry['response'].usage (if present):")
    print("=" * 70)
    resp = entry.get("response")
    if resp is not None:
        print("response type:", type(resp))
        ru = getattr(resp, "usage", "NO .usage ATTR")
        print("response.usage:", ru)
        print("response.usage type:", type(ru))
        try:
            print("as dict:", json.dumps(dict(ru), indent=2, default=str))
        except Exception as e:
            print("dict() failed:", e)
    else:
        print("no 'response' key in history entry")

print("\n" + "=" * 70)
print("5) out.label:", repr(getattr(out, "label", None)))
print("=" * 70)