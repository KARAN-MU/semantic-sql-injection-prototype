from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import time
import numpy as np

from samples import MALICIOUS, TEST

# Load NLP model
print("Loading Sentence-BERT model...")
model = SentenceTransformer("all-MiniLM-L6-v2")

# Generate embeddings
print("Generating embeddings...")
start = time.time()

malicious_embeddings = model.encode(MALICIOUS)
test_embeddings = model.encode(TEST)

elapsed = time.time() - start
print(f"Embedded {len(MALICIOUS) + len(TEST)} queries in {elapsed:.2f} seconds\n")

# Similarity threshold
THRESHOLD = 0.75

print(f"{'Query':<40} | {'Max Similarity':<14} | {'Verdict'}")
print("-" * 75)

for i, test_vec in enumerate(test_embeddings):
    scores = cosine_similarity([test_vec], malicious_embeddings)
    max_score = float(scores.max())
    verdict = "MALICIOUS" if max_score >= THRESHOLD else "BENIGN"

    print(f"{TEST[i][:40]:<40} | {max_score:<14.3f} | {verdict}")

    closest_idx = np.argmax(scores)
    if max_score > 0.5:
        print(f"   ↳ Closest match: {MALICIOUS[closest_idx]}")
