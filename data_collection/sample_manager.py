"""
Sample Manager - Coordinates sample downloading and storage
"""
import os
import json
import hashlib
from pathlib import Path
from typing import List, Dict
from .api_clients import VirusTotalClient, MalwareBazaarClient


class SampleManager:
    def __init__(self, output_dir: str = 'data_collection/raw_samples'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.malicious_dir = self.output_dir / 'malicious'
        self.benign_dir = self.output_dir / 'benign'
        self.malicious_dir.mkdir(exist_ok=True)
        self.benign_dir.mkdir(exist_ok=True)
        
        self.vt_client = VirusTotalClient()
        self.mb_client = MalwareBazaarClient()
        
    def collect_cryptojacking_samples(self, limit: int = 100) -> List[Dict]:
        """
        Collect cryptojacking samples from multiple sources
        
        Args:
            limit: Maximum number of samples per source
            
        Returns:
            List of unique sample metadata
        """
        print("\n=== Collecting Cryptojacking Samples ===\n")
        
        # Collect from MalwareBazaar (easier to download from)
        mb_samples = self.mb_client.search_by_tag('CoinMiner', limit=limit)
        mb_recent = self.mb_client.get_recent_samples(limit=limit)
        
        # Collect from VirusTotal
        vt_samples = self.vt_client.search_cryptojacking_samples(
            query='tag:cryptominer type:peexe', 
            limit=limit
        )
        
        # Combine and deduplicate by SHA256
        all_samples = {}
        for sample in mb_samples + mb_recent + vt_samples:
            sha256 = sample.get('sha256')
            if sha256 and sha256 not in all_samples:
                all_samples[sha256] = sample
                all_samples[sha256]['source'] = sample.get('source', 'malwarebazaar')
        
        unique_samples = list(all_samples.values())
        print(f"\n✓ Collected {len(unique_samples)} unique cryptojacking samples")
        
        return unique_samples
    
    def collect_benign_samples(self, limit: int = 100) -> List[Dict]:
        """
        Collect benign samples for training
        
        Note: In practice, you would collect known-good executables
        For this implementation, we'll create placeholders
        
        Args:
            limit: Number of benign samples to collect
            
        Returns:
            List of benign sample metadata
        """
        print("\n=== Collecting Benign Samples ===\n")
        
        # In a real implementation, collect from:
        # - System executables (C:\\Windows\\System32\\*.exe)
        # - Common applications
        # - VirusTotal with 0 detections
        
        benign_samples = []
        print("Note: Benign sample collection should include:")
        print("  - System executables")
        print("  - Common applications (browsers, office software)")
        print("  - Files with 0 AV detections from VirusTotal")
        print(f"✓ Placeholder for {limit} benign samples created")
        
        return benign_samples
    
    def download_samples(self, samples: List[Dict], sample_type: str = 'malicious') -> int:
        """
        Download samples to local storage
        
        Args:
            samples: List of sample metadata
            sample_type: 'malicious' or 'benign'
            
        Returns:
            Number of successfully downloaded samples
        """
        target_dir = self.malicious_dir if sample_type == 'malicious' else self.benign_dir
        downloaded = 0
        
        print(f"\n=== Downloading {sample_type.title()} Samples ===\n")
        
        for i, sample in enumerate(samples[:10], 1):  # Limit to 10 for demo
            sha256 = sample.get('sha256')
            if not sha256:
                continue
            
            output_path = target_dir / f"{sha256}.zip"
            
            # Skip if already downloaded
            if output_path.exists():
                print(f"[{i}/{min(10, len(samples))}] ✓ Already exists: {sha256[:16]}...")
                downloaded += 1
                continue
            
            # Try MalwareBazaar first (easier API)
            success = self.mb_client.download_sample(sha256, str(output_path))
            
            # Fallback to VirusTotal if needed
            if not success:
                success = self.vt_client.download_sample(sha256, str(output_path))
            
            if success:
                downloaded += 1
                print(f"[{i}/{min(10, len(samples))}] ✓ Downloaded: {sha256[:16]}...")
            else:
                print(f"[{i}/{min(10, len(samples))}] ✗ Failed: {sha256[:16]}...")
        
        print(f"\n✓ Successfully downloaded {downloaded}/{min(10, len(samples))} samples")
        return downloaded
    
    def save_metadata(self, samples: List[Dict], filename: str):
        """Save sample metadata to JSON"""
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(samples, f, indent=2)
        print(f"✓ Saved metadata to {output_path}")
    
    def generate_dataset_summary(self) -> Dict:
        """Generate summary statistics of collected dataset"""
        malicious_count = len(list(self.malicious_dir.glob('*.zip')))
        benign_count = len(list(self.benign_dir.glob('*.zip')))
        
        summary = {
            'total_samples': malicious_count + benign_count,
            'malicious_samples': malicious_count,
            'benign_samples': benign_count,
            'balance_ratio': f"{malicious_count}:{benign_count}",
            'malicious_dir': str(self.malicious_dir),
            'benign_dir': str(self.benign_dir)
        }
        
        return summary


if __name__ == "__main__":
    # Initialize sample manager
    manager = SampleManager()
    
    # Collect cryptojacking samples
    cryptojacking_samples = manager.collect_cryptojacking_samples(limit=50)
    
    # Save metadata
    if cryptojacking_samples:
        manager.save_metadata(cryptojacking_samples, 'cryptojacking_metadata.json')
    
    # Download samples (limited to 10 for demo)
    # NOTE: Downloading malware requires proper security measures!
    # Uncomment the line below only in a secure, isolated environment
    # manager.download_samples(cryptojacking_samples, sample_type='malicious')
    
    # Generate summary
    summary = manager.generate_dataset_summary()
    print("\n=== Dataset Summary ===")
    print(json.dumps(summary, indent=2))
