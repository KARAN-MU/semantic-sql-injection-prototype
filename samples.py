# samples.py

# Known malicious SQL injection patterns (reference corpus)
MALICIOUS = [
    "' OR 1=1 --",
    "' OR 'x'='x",
    "admin' --",
    "'; DROP TABLE users;--",
    "' UNION SELECT null, username, password FROM users--"
]

# Incoming queries to test
TEST = [
    "' OR 1=1 --",             # direct match
    "' OR 'a'='a",             # semantic variant
    "normal query here",       # benign
    "SELECT * FROM products",  # benign SQL
    "' OR TRUE --",            # semantic variant
    "'; DELETE FROM logs;--"   # different malicious intent
]
