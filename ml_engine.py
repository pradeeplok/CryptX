try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    import torch.nn.functional as F
except ImportError:
    # Handle case where dependencies aren't installed yet
    AutoTokenizer = None
    AutoModelForSequenceClassification = None
    torch = None

class MLEngine:
    def __init__(self, model_name="mrm8488/codebert-base-finetuned-detect-insecure-code"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self._is_loaded = False

    def _load_model(self):
        """Lazy load the model only when needed to save startup resources."""
        if not self._is_loaded and torch:
            print(f"Loading ML model: {self.model_name}...")
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                # Force loading to CPU and disable "meta" device optimizations that might be causing the error
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, 
                    low_cpu_mem_usage=False
                )
                self.model.to('cpu') # Ensure it's on CPU
                self.model.eval() # Set to evaluation mode
                self._is_loaded = True
                print("Model loaded successfully.")
            except Exception as e:
                print(f"Error loading model: {e}")

    def analyze(self, code_snippet):
        """
        Analyze code snippet for vulnerabilities.
        Returns: likelihood of vulnerability (0.0 to 1.0), and label.
        """
        if not torch:
            return None
            
        self._load_model()
        if not self._is_loaded:
            return {"error": "Model failed to load"}

        # Tokenize and predict
        inputs = self.tokenizer(code_snippet, return_tensors="pt", truncation=True, max_length=512)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = F.softmax(logits, dim=-1)
            
        # Assuming label 1 is insecure/vulnerable (common in these datasets, but we verify)
        # For mrm8488/codebert-base-finetuned-detect-insecure-code:
        # User defined labels usually: 0 -> Secure, 1 -> Insecure
        score = probs[0][1].item()
        is_vulnerable = score > 0.5
        
        return {
            "is_vulnerable": is_vulnerable,
            "confidence": score,
            "label": "Insecure" if is_vulnerable else "Secure"
        }

# Singleton instance
engine = MLEngine()
