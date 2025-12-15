import os
import sys
import io
from cipher_classifier import classifier

# Force UTF-8 output for Windows consoles/redirection
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def benchmark_sih():
    dataset_dir = os.path.join(os.path.dirname(__file__), 'sih_dataset')
    
    print(f"{'File':<15} | {'Prediction':<25} | {'Confidence':<10} | {'Reason':<40}")
    print("-" * 100)
    
    for i in range(1, 9):
        filename = f"cipher{i}.txt"
        filepath = os.path.join(dataset_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"{filename:<15} | {'FILE NOT FOUND':<25} | {'N/A':<10} | {'-'}")
            continue
            
        try:
            with open(filepath, 'r') as f:
                hex_data = f.read().strip()
                
            # Clean hex data (remove spaces/newlines)
            hex_data = hex_data.replace(' ', '').replace('\n', '')
            
            result = classifier.identify_algorithm(hex_data)
            
            top_match = result['top_candidates'][0]
            name = top_match['algorithm']
            conf = top_match['confidence']
            reason = top_match['reason']
            
            print(f"{filename:<15} | {name:<25} | {conf:<10.2%} | {reason:<40}")
            
            # Print detailed ML/Heuristic stats for debugging
            # print(f"   Stats: {result['analysis']}") 

        except Exception as e:
            print(f"{filename:<15} | {'ERROR':<25} | {'0%':<10} | {str(e)}")

if __name__ == "__main__":
    benchmark_sih()
