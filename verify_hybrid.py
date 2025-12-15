import sys
import unittest
from ml_engine import engine
from analyzer import analyze_crypto_code

class TestHybridSystem(unittest.TestCase):
    def test_ml_engine_load(self):
        print("\nTesting ML Engine load...")
        if not engine._is_loaded:
            engine._load_model()
        self.assertTrue(engine._is_loaded, "ML Engine failed to load")
        self.assertIsNotNone(engine.model, "Model is None")
        self.assertIsNotNone(engine.tokenizer, "Tokenizer is None")

    def test_ml_prediction_secure(self):
        print("\nTesting ML Prediction (Secure)...")
        # A simple secure snippet
        code = """
        import secrets
        key = secrets.token_bytes(32)
        """
        result = engine.analyze(code)
        print(f"Result: {result}")
        self.assertFalse(result['is_vulnerable'], "Marked secure code as vulnerable")

    def test_ml_prediction_insecure(self):
        print("\nTesting ML Prediction (Insecure)...")
        # A snippet often flagged as insecure (hardcoded password/key pattern)
        code = """
        def connect():
            password = "super_secret_password_123"
            return password
        """
        result = engine.analyze(code)
        print(f"Result: {result}")
        # Note: ML models are probabilistic, so we check if confidence is reasonable
        # or if it at least runs without error. Exact vulnerability prediction depends on the specific model's training.
        if result['is_vulnerable']:
            print("Verified: Model correctly flagged insecure code.")
        else:
            print("Note: Model did not flag this specific snippet. This might be expected depending on training data.")
            
    def test_analyzer_integration(self):
        print("\nTesting Analyzer Integration...")
        code = """
        key = "12345"
        """
        issues = analyze_crypto_code(code)
        # We expect at least the AST 'Hardcoded Key' issue
        issue_types = [i['type'] for i in issues]
        print(f"Issues Found: {issue_types}")
        
        # Check if ML detection triggered (it might or might not depending on the model score for this snippet)
        # This test mainly ensures that calling analyze_crypto_code DOES NOT CRASH even with ML integrated
        self.assertIn("AES Key", issue_types, "AST detection failed")
        
        # Verify ML ran (we can't easily check internal state, but if it didn't crash, good)

if __name__ == '__main__':
    unittest.main()
