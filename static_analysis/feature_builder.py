"""
Feature Builder - Combine all static features into structured dataset
"""
import pandas as pd
import os
import json
from typing import Dict, List
from .pe_analyzer import PEAnalyzer
from .string_extractor import StringExtractor


class StaticFeatureBuilder:
    def __init__(self):
        self.pe_analyzer = PEAnalyzer()
        self.string_extractor = StringExtractor()
        
    def build_features_for_sample(self, file_path: str, label: str) -> Dict:
        """
        Build complete feature vector for a single sample
        
        Args:
            file_path: Path to sample file
            label: 'malicious' or 'benign'
            
        Returns:
            Dictionary of features
        """
        features = {'file_path': file_path, 'label': label}
        
        # Extract PE features
        pe_features = self.pe_analyzer.analyze_file(file_path)
        if pe_features:
            features.update({
                'file_size': pe_features['file_size'],
                'entry_point': pe_features['entry_point'],
                'num_sections': pe_features['number_of_sections'],
                'total_entropy': pe_features['total_entropy'],
                'num_imports': pe_features['number_of_imports'],
                'num_exports': pe_features['number_of_exports'],
                'has_resources': int(pe_features['has_resources']),
                'num_resources': pe_features['number_of_resources'],
                'num_imported_dlls': len(pe_features['imported_dlls']),
                'num_suspicious_imports': len(pe_features['suspicious_imports']),
                'sha256': pe_features['sha256'],
            })
            
            # Calculate average section entropy
            if pe_features['section_entropy']:
                avg_entropy = sum(pe_features['section_entropy'].values()) / len(pe_features['section_entropy'])
                features['avg_section_entropy'] = round(avg_entropy, 2)
            else:
                features['avg_section_entropy'] = 0
        
        # Extract string features
        string_results = self.string_extractor.extract_and_analyze(file_path)
        if string_results:
            analysis = string_results['analysis']
            features.update({
                'total_strings': string_results['total_strings'],
                'num_crypto_addresses': len(analysis['crypto_addresses']),
                'num_urls': len(analysis['urls']),
                'num_mining_keywords': len(analysis['mining_keywords']),
                'suspicious_string_count': analysis['suspicious_count'],
            })
            
            # Binary flags for crypto indicators
            features['has_crypto_address'] = int(len(analysis['crypto_addresses']) > 0)
            features['has_mining_keywords'] = int(len(analysis['mining_keywords']) > 0)
            features['has_suspicious_urls'] = int(len(analysis['urls']) > 0)
        
        return features
    
    def build_dataset(self, malicious_dir: str, benign_dir: str, output_file: str):
        """
        Build complete dataset from directories of samples
        
        Args:
            malicious_dir: Directory with malicious samples
            benign_dir: Directory with benign samples
            output_file: Path to save CSV file
        """
        all_features = []
        
        print("\n=== Building Static Feature Dataset ===\n")
        
        # Process malicious samples
        if os.path.exists(malicious_dir):
            malicious_files = [f for f in os.listdir(malicious_dir) if f.endswith('.exe')]
            print(f"Processing {len(malicious_files)} malicious samples...")
            
            for i, filename in enumerate(malicious_files, 1):
                file_path = os.path.join(malicious_dir, filename)
                try:
                    features = self.build_features_for_sample(file_path, label='malicious')
                    all_features.append(features)
                    if i % 10 == 0:
                        print(f"  Processed {i}/{len(malicious_files)} malicious samples")
                except Exception as e:
                    print(f"  ✗ Error processing {filename}: {e}")
        
        # Process benign samples
        if os.path.exists(benign_dir):
            benign_files = [f for f in os.listdir(benign_dir) if f.endswith('.exe')]
            print(f"\nProcessing {len(benign_files)} benign samples...")
            
            for i, filename in enumerate(benign_files, 1):
                file_path = os.path.join(benign_dir, filename)
                try:
                    features = self.build_features_for_sample(file_path, label='benign')
                    all_features.append(features)
                    if i % 10 == 0:
                        print(f"  Processed {i}/{len(benign_files)} benign samples")
                except Exception as e:
                    print(f"  ✗ Error processing {filename}: {e}")
        
        # Create DataFrame
        df = pd.DataFrame(all_features)
        
        # Save to CSV
        df.to_csv(output_file, index=False)
        print(f"\n✓ Dataset saved to {output_file}")
        print(f"✓ Total samples: {len(df)}")
        print(f"  - Malicious: {len(df[df['label'] == 'malicious'])}")
        print(f"  - Benign: {len(df[df['label'] == 'benign'])}")
        
        # Display summary statistics
        print("\n=== Feature Summary ===")
        numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
        print(df[numeric_cols].describe())
        
        return df


if __name__ == "__main__":
    # Build dataset
    builder = StaticFeatureBuilder()
    
    # Example paths
    malicious_dir = "data_collection/raw_samples/malicious"
    benign_dir = "data_collection/raw_samples/benign"
    output_file = "static_analysis/features/static_features.csv"
    
    # Create output directory
    os.makedirs("static_analysis/features", exist_ok=True)
    
    # Build dataset
    df = builder.build_dataset(malicious_dir, benign_dir, output_file)
