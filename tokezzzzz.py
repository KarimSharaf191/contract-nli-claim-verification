import json
import tiktoken

# Load all three splits
splits = {}
for split in ["train", "dev", "test"]:
    path = f"C:\\Users\\Computec\\Downloads\\contract-nli (1)\\contract-nli\\{split}.json"
    with open(path) as f:
        splits[split] = json.load(f)

# Use cl100k_base encoding (same as GPT-4 / most modern models)
enc = tiktoken.get_encoding("cl100k_base")

results = {}

for split_name, data in splits.items():
    split_results = []
    for doc in data["documents"]:
        tokens = enc.encode(doc["text"])
        split_results.append({
            "id": doc["id"],
            "file_name": doc["file_name"],
            "document_type": doc["document_type"],
            "num_tokens": len(tokens)
        })
    results[split_name] = split_results

# Print per-split summary
for split_name, docs in results.items():
    token_counts = [d["num_tokens"] for d in docs]
    print(f"\n=== {split_name} ({len(docs)} docs) ===")
    print(f"  Average : {sum(token_counts)/len(token_counts):.0f} tokens")
    print(f"  Min     : {min(token_counts)} tokens")
    print(f"  Max     : {max(token_counts)} tokens")
    print(f"  > 12K   : {sum(1 for t in token_counts if t > 12000)} docs")

# Print per-document breakdown (optional, can comment out)
print("\n=== Per-document token counts ===")
for split_name, docs in results.items():
    print(f"\n--- {split_name} ---")
    for d in sorted(docs, key=lambda x: x["num_tokens"], reverse=True):
        print(f"  {d['id']:>4} | {d['num_tokens']:>6} tokens | {d['file_name']}")