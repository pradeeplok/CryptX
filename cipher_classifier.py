import joblib
import os
import numpy as np
from collections import Counter
import re
from scipy import stats
import zlib

class CipherClassifier:
    """
    Identifies cryptographic algorithms from ciphertext using advanced statistical analysis & ML features.
    Compliant with SIH-1681 Requirements.
    """
    
    def __init__(self):
        self.algorithm_signatures = {
            'AES-128': {'block_size': 16, 'key_sizes': [16]},
            'AES-192': {'block_size': 16, 'key_sizes': [24]},
            'AES-256': {'block_size': 16, 'key_sizes': [32]},
            'DES': {'block_size': 8, 'key_sizes': [8]},
            '3DES': {'block_size': 8, 'key_sizes': [24]},
            'Blowfish': {'block_size': 8, 'key_sizes': [4, 56]},
            'ChaCha20': {'block_size': 64, 'stream': True},
            'RSA-1024': {'asymmetric': True, 'size': 128},
            'RSA-2048': {'asymmetric': True, 'size': 256},
            'RSA-4096': {'asymmetric': True, 'size': 512}
        }
        self.model = None
        self.load_model()
        
    def load_model(self):
        """Load the trained Random Forest model."""
        try:
            model_path = os.path.join(os.path.dirname(__file__), 'cipher_model.pkl')
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                print("Global ML Model loaded successfully.")
            else:
                print("ML Model not found. Running in Heuristic Mode.")
        except Exception as e:
            print(f"Error loading ML model: {e}")

    def hex_to_bytes(self, hex_string):
        """Convert hex string to bytes."""
        hex_clean = re.sub(r'[^0-9A-Fa-f]', '', hex_string)
        try:
            return bytes.fromhex(hex_clean)
        except ValueError:
            raise ValueError("Invalid hexadecimal string")
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of byte data."""
        if len(data) == 0:
            return 0
        
        counter = Counter(data)
        probabilities = [count / len(data) for count in counter.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy

    def detect_block_size(self, data):
        """
        Detect likely block size by looking for repeating patterns (ECB mode indicator).
        Returns most likely block sizes.
        """
        likely_sizes = []
        block_sizes = [8, 16, 32, 64]
        
        for bs in block_sizes:
            if len(data) % bs == 0:
                blocks = [data[i:i+bs] for i in range(0, len(data), bs)]
                unique_blocks = len(set(blocks))
                total_blocks = len(blocks)
                
                # If there are repeated blocks, it might be ECB mode
                repetition_ratio = 1 - (unique_blocks / total_blocks)
                
                if repetition_ratio > 0.1:  # More than 10% repetition
                    likely_sizes.append((bs, repetition_ratio, 'ECB mode likely'))
                elif len(data) % bs == 0:
                    likely_sizes.append((bs, 0, 'Valid block alignment'))
        
        return likely_sizes if likely_sizes else [(len(data), 0, 'Unknown')]

    def analyze_advanced_stats(self, data):
        """
        Extract advanced statistical features (SIH-1681 Requirement 3.1).
        - Skewness
        - Kurtosis
        - Chi-Square P-value
        - Autocorrelation (Lag 1)
        """
        # 1. Byte Distribution (Histogram)
        byte_array = np.frombuffer(data, dtype=np.uint8)
        
        # 2. Skewness & Kurtosis
        skew = stats.skew(byte_array)
        kurtosis = stats.kurtosis(byte_array)
        
        # 3. Chi-Square Test for Uniformity
        # Expected count for each byte value (0-255) is len(data) / 256
        f_obs = np.bincount(byte_array, minlength=256)
        f_exp = np.full(256, len(data) / 256)
        chi2_stat, p_value = stats.chisquare(f_obs, f_exp)
        
        # 4. Autocorrelation (Lag 1)
        # Check if byte[i] is correlated with byte[i-1]
        if len(byte_array) > 1:
            ac_1 = np.corrcoef(byte_array[:-1], byte_array[1:])[0, 1]
        else:
            ac_1 = 0
            
        return {
            'skewness': round(float(skew), 4),
            'kurtosis': round(float(kurtosis), 4),
            'chi2_stat': round(float(chi2_stat), 2),
            'chi2_p_value': round(float(p_value), 6),
            'autocorrelation': round(float(ac_1), 4)
        }

    def analyze_compression(self, data):
        """
        Calculate compression ratio (SIH-1681 Requirement 3.4).
        Encrypted data should have ratio ~1.0 (incompressible).
        """
        compressed = zlib.compress(data)
        ratio = len(data) / len(compressed)
        return round(ratio, 4)

    def analyze_ngrams(self, data, n=2):
        """
        Analyze N-gram repetition (SIH-1681 Requirement 3.3).
        """
        if len(data) < n:
            return 0
        
        # Sliding window n-grams
        ngrams = [data[i:i+n] for i in range(len(data)-n+1)]
        unique_ngrams = len(set(ngrams))
        
        # Repetition ratio (0 = all unique, 1 = all same)
        total_ngrams = len(ngrams)
        if total_ngrams == 0: return 0
        
        repetition = 1 - (unique_ngrams / total_ngrams)
        return round(repetition, 4)

    def extract_features_vector(self, data):
        """
        Extract a flattened feature vector for ML training/inference.
        Returns: [entropy, block_8_rep, block_16_rep, block_32_rep, skew, kurtosis, chi2_stat, autocorrelation, compression_ratio, bigram_rep]
        """
        # 1. Entropy
        entropy = self.calculate_entropy(data)
        
        # 2. Block Analysis
        block_info = self.detect_block_size(data)
        # Convert block info to features: [rep_8, rep_16, rep_32]
        block_reps = {8: 0.0, 16: 0.0, 32: 0.0}
        for bs, rep, _ in block_info:
            if bs in block_reps:
                block_reps[bs] = rep
        
        # 3. Advanced Stats
        stats = self.analyze_advanced_stats(data)
        
        # 4. Compression
        comp_ratio = self.analyze_compression(data)
        
        # 5. N-grams
        bigram_rep = self.analyze_ngrams(data, n=2)
        
        return [
            entropy,
            block_reps[8],
            block_reps[16],
            block_reps[32],
            stats['skewness'],
            stats['kurtosis'],
            stats['chi2_stat'],
            stats['autocorrelation'],
            comp_ratio,
            bigram_rep
        ]

    def identify_algorithm(self, hex_string):
        """
        Main identification method.
        Returns a ranked list of probable algorithms with confidence scores.
        """
        try:
            data = self.hex_to_bytes(hex_string)
        except ValueError as e:
            return {'error': str(e)}
        
        if len(data) == 0:
            return {'error': 'Empty input'}
        
        # Feature extraction
        entropy = self.calculate_entropy(data)
        block_info = self.detect_block_size(data)
        advanced_stats = self.analyze_advanced_stats(data)
        compression_ratio = self.analyze_compression(data)
        bigram_rep = self.analyze_ngrams(data, n=2)
        
        candidates = []
        
        # --- 1. Machine Learning Prediction (Priority) ---
        if self.model:
            try:
                features = self.extract_features_vector(data)
                # Reshape for single sample
                feats_reshaped = np.array(features).reshape(1, -1)
                
                # Get probabilities
                probs = self.model.predict_proba(feats_reshaped)[0]
                classes = self.model.classes_
                
                # Get top 3
                top_indices = np.argsort(probs)[-3:][::-1]
                
                for idx in top_indices:
                    prob = probs[idx]
                    if prob > 0.05: # Threshold
                        candidates.append({
                            'algorithm': classes[idx],
                            'confidence': round(float(prob), 4),
                            'reason': f'ML Model Prediction ({prob*100:.1f}% confidence)'
                        })
            except Exception as e:
                print(f"ML Prediction failed: {e}")
        
        # --- 2. Heuristic Rules (Fallback / Verification) ---
        # If ML is unsure or unavailable, add heuristic findings
        
        # Check block-based algorithms
        for bs, rep_ratio, note in block_info:
            if bs == 16:
                if rep_ratio > 0.1:
                    candidates.append({
                        'algorithm': 'AES (ECB Mode)',
                        'confidence': min(0.85 + rep_ratio, 0.99),
                        'reason': f'Heuristic: 16-byte blocks with {rep_ratio:.1%} repetition'
                    })
            elif bs == 8:
                if rep_ratio > 0.1:
                     candidates.append({
                        'algorithm': 'DES/3DES (ECB Mode)',
                        'confidence': min(0.80 + rep_ratio, 0.95),
                        'reason': f'Heuristic: 8-byte blocks with {rep_ratio:.1%} repetition'
                    })
        
        # Check for RSA length match
        if len(data) in [128, 256, 512]:
             candidates.append({
                'algorithm': f'RSA-{len(data)*8}',
                'confidence': 0.60,
                'reason': f'Heuristic: Matching RSA key length'
            })

        # Deduplicate candidates (prefer ML if same algorithm)
        # Simple deduplication by algorithm name
        unique_candidates = {}
        for c in candidates:
            name = c['algorithm']
            if name not in unique_candidates or c['confidence'] > unique_candidates[name]['confidence']:
                unique_candidates[name] = c
        
        final_candidates = list(unique_candidates.values())
        final_candidates.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Force "Unknown" if no candidates
        if not final_candidates:
             final_candidates.append({
                'algorithm': 'Unknown',
                'confidence': 0.0,
                'reason': 'No substantial matches found'
            })

        # Prepare Analysis Report for UI
        return {
            'top_candidates': final_candidates[:3],
            'analysis': {
                'data_length': len(data),
                'entropy': round(entropy, 3),
                'entropy_max': 8.0,
                'advanced': advanced_stats,
                'compression_ratio': compression_ratio,
                'bigram_repetition': f"{bigram_rep:.2%}",
                'block_analysis': [
                    {
                        'block_size': bs,
                        'repetition_ratio': round(rep, 3),
                        'note': note
                    }
                    for bs, rep, note in block_info[:3]
                ]
            }
        }


    def explain_prediction(self, data):
        """
        Explain why the model made a specific prediction (SIH-1681 Phase 3).
        Uses SHAP (SHapley Additive exPlanations) to attribute score to features.
        """
        if not self.model:
            return {'error': 'ML Model not loaded'}

        try:
            import shap
            
            # 1. Extract features for this single sample
            features = self.extract_features_vector(data)
            feats_reshaped = np.array(features).reshape(1, -1)
            
            # 2. Initialize Explainer (TreeExplainer is optimized for Random Forest)
            # Note: We initialize it here, but in production, this should be cached.
            explainer = shap.TreeExplainer(self.model)
            
            # DEBUG: Print structure BEFORE crash
            print(f"DEBUG: feats_reshaped shape: {feats_reshaped.shape}")
            print(f"DEBUG: Model classes: {self.model.classes_}")
            
            # 3. Calculate SHAP values
            # 3. Calculate SHAP values
            # shap_values can be a list of arrays (one per class) OR a single 3D array (samples, features, classes)
            shap_values = explainer.shap_values(feats_reshaped, check_additivity=False)
            
            # 4. Get the predicted class index
            probs = self.model.predict_proba(feats_reshaped)[0]
            predicted_class_idx = np.argmax(probs)
            predicted_class_name = self.model.classes_[predicted_class_idx]
            
            # 5. Get feature importance for the predicted class
            importance = None
            
            if isinstance(shap_values, list):
                # Legacy SHAP behavior: List of [samples, features] per class
                if predicted_class_idx < len(shap_values):
                    importance = shap_values[predicted_class_idx][0]
                else:
                    return {'error': 'SHAP class index mismatch (List)'}
            elif isinstance(shap_values, np.ndarray):
                # Newer SHAP behavior: Array of shape (samples, features, classes) or (samples, features)
                if len(shap_values.shape) == 3: # (samples, features, classes)
                    # We want the importance for the 0th sample, all features, for the specific class
                    importance = shap_values[0, :, predicted_class_idx]
                elif len(shap_values.shape) == 2: # (samples, features) - Binary case?
                    # If binary, usually index 1 is positive class? Or it returns just one array?
                    # Generally for RF binary, it might be 1 array.
                    importance = shap_values[0]
                else:
                     return {'error': f'Unexpected SHAP array shape: {shap_values.shape}'}
            else:
                 return {'error': f'Unexpected SHAP return type: {type(shap_values)}'}

            feature_names = [
                'Entropy', 'Block 8 Rep', 'Block 16 Rep', 'Block 32 Rep',
                'Skewness', 'Kurtosis', 'Chi2 Stat', 'Autocorrelation',
                'Compression', 'Bigram Rep'
            ]
            
            # 6. Format explanation
            explanation = []
            for name, value, impact in zip(feature_names, features, importance):
                explanation.append({
                    'feature': name,
                    'value': round(float(value), 4),
                    'impact': round(float(impact), 4) # Positive means "pushes towards this class"
                })
            
            # Sort by absolute impact (most influential first)
            explanation.sort(key=lambda x: abs(x['impact']), reverse=True)
            
            return {
                'predicted_class': predicted_class_name,
                'confidence': round(float(probs[predicted_class_idx]), 4),
                'top_features': explanation[:5] # Return top 5 influencers
            }
            
        except Exception as e:
            print(f"Explanation failed: {e}")
            return {'error': str(e)}

# Singleton instance
classifier = CipherClassifier()
