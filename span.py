import json

with open("C:\\Users\\Computec\\Downloads\\contract-nli (1)\\contract-nli\\train.json") as f:
    data = json.load(f)

def get_evidence_text(document, annotation_span_indices):
    text = document["text"]
    span_boundaries = document["spans"]
    return [text[span_boundaries[idx][0]:span_boundaries[idx][1]] 
            for idx in annotation_span_indices]

doc = data["documents"][0]
annotations = doc["annotation_sets"][0]["annotations"]

# print all hypotheses for the first document
for nda_key, annotation in annotations.items():
    hypothesis = data["labels"][nda_key]["hypothesis"]
    choice = annotation["choice"]
    print(f"\n{nda_key} | {choice}")
    print(f"H: {hypothesis}")
    if choice != "NotMentioned":
        for i, span_text in enumerate(get_evidence_text(doc, annotation["spans"])):
            print(f"  Evidence {i}: {span_text}")