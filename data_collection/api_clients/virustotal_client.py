"""
VirusTotal API Client for fetching cryptojacking samples
"""
import os
import requests
import time
import json
from typing import Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {
            'x-apikey': self.api_key,
            'Accept': 'application/json'
        }
        self.rate_limit_delay = 15  # seconds between requests for free tier
        self.timeout_seconds = 8
    
    def search_cryptojacking_samples(self, query: str = 'tag:cryptominer', limit: int = 100) -> List[Dict]:
        """
        Search for cryptojacking/cryptominer samples
        
        Args:
            query: Search query (e.g., 'tag:cryptominer', 'type:peexe cryptominer')
            limit: Maximum number of results
            
        Returns:
            List of sample metadata dictionaries
        """
        endpoint = f"{self.base_url}/intelligence/search"
        params = {
            'query': query,
            'limit': limit
        }
        
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=self.timeout_seconds)
            response.raise_for_status()
            data = response.json()
            
            samples = []
            for item in data.get('data', []):
                attributes = item.get('attributes', {})
                samples.append({
                    'sha256': attributes.get('sha256'),
                    'md5': attributes.get('md5'),
                    'sha1': attributes.get('sha1'),
                    'file_type': attributes.get('type_description'),
                    'size': attributes.get('size'),
                    'first_seen': attributes.get('first_submission_date'),
                    'detection_ratio': f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/{sum(attributes.get('last_analysis_stats', {}).values())}",
                    'tags': attributes.get('tags', []),
                    'names': attributes.get('names', [])
                })
            
            print(f"✓ Found {len(samples)} samples from VirusTotal")
            return samples
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Error searching VirusTotal: {e}")
            return []
    
    def get_file_info(self, file_hash: str) -> Optional[Dict]:
        """
        Get detailed information about a specific file
        
        Args:
            file_hash: SHA256, MD5, or SHA1 hash
            
        Returns:
            File information dictionary
        """
        endpoint = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=self.timeout_seconds)
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get('data', {}).get('attributes', {})
            return {
                'sha256': attributes.get('sha256'),
                'file_type': attributes.get('type_description'),
                'size': attributes.get('size'),
                'creation_date': attributes.get('creation_date'),
                'detection_ratio': attributes.get('last_analysis_stats'),
                'pe_info': attributes.get('pe_info', {}),
                'sandbox_verdicts': attributes.get('sandbox_verdicts', {})
            }
            
        except requests.exceptions.HTTPError as e:
            if getattr(e.response, "status_code", None) == 404:
                return None
            print(f"✗ Error getting file info for {file_hash}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"✗ Error getting file info for {file_hash}: {e}")
            return None
    
    def download_sample(self, file_hash: str, output_path: str) -> bool:
        """
        Download a malware sample (requires elevated API key)
        
        Args:
            file_hash: SHA256 hash
            output_path: Path to save the file
            
        Returns:
            True if successful, False otherwise
        """
        endpoint = f"{self.base_url}/files/{file_hash}/download"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=self.timeout_seconds)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                f.write(response.content)
            
            print(f"✓ Downloaded sample {file_hash} to {output_path}")
            time.sleep(self.rate_limit_delay)  # Respect rate limits
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Error downloading {file_hash}: {e}")
            return False
    
    def save_metadata(self, samples: List[Dict], output_file: str):
        """Save sample metadata to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(samples, f, indent=2)
        print(f"✓ Saved metadata for {len(samples)} samples to {output_file}")


if __name__ == "__main__":
    # Test the client
    client = VirusTotalClient()
    
    # Search for cryptomining samples
    samples = client.search_cryptojacking_samples(query='tag:cryptominer type:peexe', limit=10)
    
    if samples:
        # Save metadata
        client.save_metadata(samples, 'data_collection/virustotal_samples.json')
        
        # Get detailed info for first sample
        if samples[0]['sha256']:
            info = client.get_file_info(samples[0]['sha256'])
            print(f"\nSample details: {json.dumps(info, indent=2)}")
