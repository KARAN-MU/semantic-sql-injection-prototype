\## Findings



\- Semantic variants like OR 1=1, OR 'a'='a, OR TRUE cluster together.

\- Regex alone misses some variants; semantic embeddings generalize better.

\- Some benign SQL may appear similar; threshold tuning is required.

\- Embedding latency is low for small batches (~0.07s).



