import sys
import io
# Force UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

try:
    print("Testing SHAP integration...")
    from cipher_classifier import classifier
    
    if not classifier.model:
        print("Error: Model not loaded in classifier.")
        sys.exit(1)
        
    print("Model loaded.")
    
    # Test with dummy data (AES-128 sample)
    # 16 bytes of random data for block test
    hex_sample = "00112233445566778899aabbccddeeff"
    data = bytes.fromhex(hex_sample)
    
    print("Running explain_prediction...")
    result = classifier.explain_prediction(data)
    
    if 'error' in result:
        print(f"Explanation failed: {result['error']}")
        sys.exit(1)
        
    print("Explanation Success!")
    print(f"Predicted Class: {result['predicted_class']}")
    print(f"Confidence: {result['confidence']}")
    print("Top Features:")
    for f in result['top_features']:
        print(f" - {f['feature']}: {f['impact']} (Val: {f['value']})")
        
except ImportError as e:
    print(f"ImportError: {e}")
    print("Please ensure 'shap' is installed: pip install shap")
except Exception as e:
    print(f"Unexpected Error: {e}")
