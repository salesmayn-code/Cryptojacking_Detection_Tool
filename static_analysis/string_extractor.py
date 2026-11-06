"""
String Extractor - Extract suspicious strings from binaries
"""
import re
from typing import List, Dict, Iterator, Optional, Set


class StringExtractor:
    ANALYSIS_BATCH_STRINGS = 2000
    CHUNK_BYTES = 4 * 1024 * 1024
    CHUNK_OVERLAP_BYTES = 4096

    def __init__(self, max_scan_bytes: Optional[int] = None):
        # Only the first max_scan_bytes of a file are read; None reads the whole file.
        self.max_scan_bytes = max_scan_bytes

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
        try:
            strings = set()
            for data in self._read_chunks(file_path):
                strings.update(self._strings_from_bytes(data, min_length))
            return list(strings)

        except Exception as e:
            print(f"✗ Error extracting strings from {file_path}: {e}")
            return []

    def _read_chunks(self, file_path: str) -> Iterator[bytes]:
        """Yield the whole file, or overlapping chunks of its start when a limit is set."""
        with open(file_path, 'rb') as f:
            if self.max_scan_bytes is None:
                yield f.read()
                return

            remaining = self.max_scan_bytes
            overlap = b''
            while remaining > 0:
                chunk = f.read(min(self.CHUNK_BYTES, remaining))
                if not chunk:
                    return
                remaining -= len(chunk)
                yield overlap + chunk
                overlap = chunk[-self.CHUNK_OVERLAP_BYTES:]

    @staticmethod
    def _strings_from_bytes(data: bytes, min_length: int = 4) -> Set[str]:
        # Extract ASCII strings
        ascii_pattern = b'[\x20-\x7e]{' + str(min_length).encode() + b',}'
        strings = {s.decode('ascii', errors='ignore') for s in re.findall(ascii_pattern, data)}

        # Extract Unicode strings
        unicode_pattern = b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}'
        strings.update(s.decode('utf-16-le', errors='ignore') for s in re.findall(unicode_pattern, data))
        return strings
    
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
        
        # Newlines can't match any pattern below, so joined strings can't match across each other.
        for start in range(0, len(strings), self.ANALYSIS_BATCH_STRINGS):
            text = "\n".join(strings[start:start + self.ANALYSIS_BATCH_STRINGS])
            text_lower = text.lower()

            # Check for cryptocurrency addresses
            for addr_type, pattern in self.crypto_patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    analysis['crypto_addresses'].extend([(addr_type, m) for m in matches])

            # Check for URLs
            urls = re.findall(self.url_pattern, text)
            if urls:
                analysis['urls'].extend(urls)

            # Check for mining keywords
            for keyword in self.mining_keywords:
                if keyword in text_lower:
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
        total_strings = 0
        found = {'crypto_addresses': set(), 'urls': set(), 'mining_keywords': set(), 'mining_pools': set()}

        try:
            # Analyzing each chunk as it is read avoids holding every string in memory at once.
            for data in self._read_chunks(file_path):
                strings = list(self._strings_from_bytes(data))
                total_strings += len(strings)
                chunk_analysis = self.analyze_strings(strings)
                for key, values in found.items():
                    values.update(chunk_analysis[key])
        except Exception as e:
            print(f"✗ Error extracting strings from {file_path}: {e}")
        print(f"✓ Extracted {total_strings} strings")

        print("Analyzing strings for suspicious patterns...")
        analysis = {key: list(values) for key, values in found.items()}
        analysis['suspicious_count'] = (
            len(found['crypto_addresses']) + len(found['urls']) + len(found['mining_keywords'])
        )
        print(f"✓ Found {analysis['suspicious_count']} suspicious indicators")

        return {
            'total_strings': total_strings,
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
