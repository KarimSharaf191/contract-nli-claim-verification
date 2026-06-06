import json

with open("C:\\Users\\Computec\\Downloads\\contract-nli (1)\\contract-nli\\train.json") as f:
    data = json.load(f)

doc = data["documents"][0]
span_idx = 19
start, end = doc["spans"][span_idx]

print(f"Span boundaries: [{start}, {end}]")
print(f"Text: {doc['text'][start:end]}")