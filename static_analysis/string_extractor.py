"""
String Extractor - Extract suspicious strings from binaries
"""
import re
from typing import List, Dict


class StringExtractor:
    def __init__(self):
        # Cryptocurrency-related patterns
        self.crypto_patterns = {
            'bitcoin_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'ethereum_address': r'\b0x[a-fA-F0-9]{40}\b',
            'monero_address': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
            'mining_pool': r'(pool\.|stratum\+tcp://|mining\.)',
            'wallet': r'(wallet|address|xpub)',
        }
        
        # Mining-related keywords
        self.mining_keywords = [
            'xmrig', 'xmrig-notls', 'xmr-stak', 'cpuminer', 'minerd',
            'ethminer', 'claymore', 'phoenixminer', 'nbminer', 'lolminer',
            'trex', 't-rex', 'cryptonight', 'randomx', 'ethash', 'equihash',
            'stratum', 'minexmr', 'supportxmr', 'nanopool', '2miners', 'monero'
        ]
        
        # Suspicious URLs
        self.url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    
    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """
        Extract ASCII and Unicode strings from binary file
        
        Args:
            file_path: Path to binary file
            min_length: Minimum string length to extract
            
        Returns:
            List of extracted strings
        """
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            ascii_pattern = b'[\x20-\x7e]{' + str(min_length).encode() + b',}'
            ascii_strings = re.findall(ascii_pattern, data)
            strings.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])
            
            # Extract Unicode strings
            unicode_pattern = b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}'
            unicode_strings = re.findall(unicode_pattern, data)
            strings.extend([s.decode('utf-16-le', errors='ignore') for s in unicode_strings])
            
            return list(set(strings))  # Remove duplicates
            
        except Exception as e:
            print(f"✗ Error extracting strings from {file_path}: {e}")
            return []
    
    def analyze_strings(self, strings: List[str]) -> Dict:
        """
        Analyze extracted strings for suspicious patterns
        
        Args:
            strings: List of extracted strings
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'crypto_addresses': [],
            'mining_pools': [],
            'urls': [],
            'mining_keywords': [],
            'suspicious_count': 0
        }
        
        for string in strings:
            string_lower = string.lower()
            
            # Check for cryptocurrency addresses
            for addr_type, pattern in self.crypto_patterns.items():
                matches = re.findall(pattern, string)
                if matches:
                    analysis['crypto_addresses'].extend([(addr_type, m) for m in matches])
            
            # Check for URLs
            urls = re.findall(self.url_pattern, string)
            if urls:
                analysis['urls'].extend(urls)
            
            # Check for mining keywords
            for keyword in self.mining_keywords:
                if keyword in string_lower:
                    analysis['mining_keywords'].append(keyword)
        
        # Count unique suspicious indicators
        analysis['suspicious_count'] = (
            len(set(analysis['crypto_addresses'])) +
            len(set(analysis['urls'])) +
            len(set(analysis['mining_keywords']))
        )
        
        # Remove duplicates
        analysis['crypto_addresses'] = list(set(analysis['crypto_addresses']))
        analysis['urls'] = list(set(analysis['urls']))
        analysis['mining_keywords'] = list(set(analysis['mining_keywords']))
        
        return analysis
    
    def extract_and_analyze(self, file_path: str) -> Dict:
        """
        Complete extraction and analysis pipeline
        
        Args:
            file_path: Path to binary file
            
        Returns:
            Dictionary with all results
        """
        print(f"Extracting strings from {file_path}...")
        strings = self.extract_strings(file_path)
        print(f"✓ Extracted {len(strings)} unique strings")
        
        print("Analyzing strings for suspicious patterns...")
        analysis = self.analyze_strings(strings)
        print(f"✓ Found {analysis['suspicious_count']} suspicious indicators")
        
        return {
            'total_strings': len(strings),
            'analysis': analysis
        }


if __name__ == "__main__":
    # Test the extractor
    extractor = StringExtractor()
    
    # Example usage
    sample_path = "data_collection/raw_samples/malicious/sample.exe"
    results = extractor.extract_and_analyze(sample_path)
    
    print("\n=== String Analysis Results ===")
    print(f"Total strings: {results['total_strings']}")
    print(f"Crypto addresses: {results['analysis']['crypto_addresses'][:5]}")  # Show first 5
    print(f"URLs found: {results['analysis']['urls'][:5]}")
    print(f"Mining keywords: {results['analysis']['mining_keywords'][:10]}")
    print(f"Suspicious count: {results['analysis']['suspicious_count']}")
