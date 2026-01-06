# improved_prototype.py
import re
import numpy as np
from sentence_transformers import SentenceTransformer
import time

class ImprovedSQLInjectionDetector:
    def __init__(self):
        print("Loading Sentence-BERT model...")
        self.model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        
        # Known malicious patterns - EXPAND THIS LIST
        self.malicious_patterns = [
            "' OR 1=1 --",
            "' OR '1'='1",
            "' OR 'x'='x",
            "admin' --",
            "' UNION SELECT",
            "'; DROP TABLE",
            "'; DELETE FROM",
            "' OR TRUE --",
            "' OR 'a'='a",
            "1' OR '1'='1",
            "' OR 1=1#",
            "' OR '1'='1'#",
        ]
        
        print("Generating embeddings for malicious patterns...")
        self.malicious_embeddings = self.model.encode(self.malicious_patterns)
        print(f"Loaded {len(self.malicious_patterns)} malicious patterns")
        
        # Dangerous regex patterns
        self.dangerous_regex = [
            r"\b(OR|AND)\s+['\"]?[0-9a-zA-Z]['\"]?\s*=\s*['\"]?[0-9a-zA-Z]['\"]?",  # ' OR 'a'='a
            r"'.*(OR|AND).*--",  # SQL comment patterns
            r"'.*(OR|AND).*#",   # MySQL comment patterns
            r";\s*\w+;",  # Query chaining
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(FROM|INTO|TABLE|VALUES)\b",  # SQL commands
            r"'.*(OR|AND).*\s*=\s*['\"]?\w+['\"]?",  # General = patterns
        ]
    
    def calculate_similarity(self, query):
        """Calculate semantic similarity with known malicious patterns"""
        query_embedding = self.model.encode([query])
        similarities = np.dot(self.malicious_embeddings, query_embedding.T).flatten()
        max_similarity = float(np.max(similarities))
        closest_pattern = self.malicious_patterns[np.argmax(similarities)]
        return max_similarity, closest_pattern
    
    def check_patterns(self, query):
        """Check for dangerous regex patterns"""
        for pattern in self.dangerous_regex:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        return False
    
    def analyze_query(self, query, semantic_threshold=0.7):
        """Hybrid analysis using both semantic similarity and pattern matching"""
        # Step 1: Semantic similarity check
        similarity_score, closest_pattern = self.calculate_similarity(query)
        
        # Step 2: Pattern matching check
        has_dangerous_pattern = self.check_patterns(query)
        
        # Step 3: Decision logic
        verdict = "BENIGN"
        detection_method = "semantic"
        
        if similarity_score > semantic_threshold:
            verdict = "MALICIOUS"
            detection_method = "semantic"
        elif has_dangerous_pattern:
            verdict = "MALICIOUS"
            detection_method = "pattern"
            similarity_score = 1.0  # Override for display
            closest_pattern = "Regex pattern match"
        
        return {
            "query": query,
            "similarity": similarity_score,
            "verdict": verdict,
            "closest_pattern": closest_pattern,
            "detection_method": detection_method
        }
    
    def test_queries(self, test_queries):
        """Test multiple queries"""
        print("\n" + "="*80)
        print("SQL INJECTION DETECTOR (Improved Hybrid Model)")
        print("="*80)
        print(f"{'Query':<40} | {'Similarity':<10} | {'Method':<10} | {'Verdict':<10}")
        print("-" * 80)
        
        for query in test_queries:
            result = self.analyze_query(query)
            
            print(f"{result['query'][:40]:<40} | "
                  f"{result['similarity']:.3f} | "
                  f"{result['detection_method']:<10} | "
                  f"{result['verdict']:<10}")
            
            if result['verdict'] == "MALICIOUS":
                print(f"   ↳ Detected as: {result['closest_pattern'][:50]}")

def main():
    # Initialize detector
    detector = ImprovedSQLInjectionDetector()
    
    # Test queries
    test_queries = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "normal query here",
        "SELECT * FROM products",
        "' OR TRUE --",
        "'; DELETE FROM logs;--",
        "admin' --",
        "' UNION SELECT username, password FROM users",
        "valid_user_login",
        "1' OR '1'='1",
        "'; DROP TABLE users; --",
    ]
    
    # Run tests
    detector.test_queries(test_queries)
    
    # Interactive mode
    print("\n" + "="*80)
    print("INTERACTIVE MODE (type 'quit' to exit)")
    print("="*80)
    
    while True:
        user_query = input("\nEnter SQL query to analyze: ").strip()
        if user_query.lower() in ['quit', 'exit', 'q']:
            break
        
        result = detector.analyze_query(user_query)
        print(f"\nQuery: {result['query']}")
        print(f"Semantic Similarity: {result['similarity']:.3f}")
        print(f"Detection Method: {result['detection_method']}")
        print(f"Verdict: {result['verdict']}")
        if result['verdict'] == "MALICIOUS":
            print(f"Matched Pattern: {result['closest_pattern']}")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"\nTotal execution time: {time.time() - start_time:.2f} seconds")