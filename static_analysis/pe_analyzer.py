"""
PE Binary Analyzer - Extract features from PE executables
"""
import pefile
import os
import math
from collections import Counter
from typing import Dict, Optional
import hashlib


class PEAnalyzer:
    ENTROPY_CHUNK_BYTES = 1024 * 1024

    def __init__(self, max_scan_bytes: Optional[int] = None):
        # Entropy covers only the first max_scan_bytes of a file; None covers the whole file.
        self.max_scan_bytes = max_scan_bytes
        self.suspicious_sections = ['.text', '.data', '.rsrc', '.reloc']
        
    def analyze_file(self, file_path: str) -> Optional[Dict]:
        """
        Analyze a PE file and extract features
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Dictionary of extracted features
        """
        if not os.path.exists(file_path):
            print(f"✗ File not found: {file_path}")
            return None
        
        try:
            pe = pefile.PE(file_path, fast_load=True)
            # With a scan limit, skip export and resource tables: they can be large, and
            # their counts are then reported as 0.
            directories = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            if self.max_scan_bytes is None:
                directories += [
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                ]
            pe.parse_data_directories(directories=directories)

            features = {
                # File properties
                'file_size': os.path.getsize(file_path),
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'number_of_sections': len(pe.sections),
                'image_base': pe.OPTIONAL_HEADER.ImageBase,
                
                # Section features
                'section_names': [section.Name.decode().strip('\x00') for section in pe.sections],
                'section_entropy': self._calculate_section_entropy(pe),
                'total_entropy': self._calculate_total_entropy(file_path),
                
                # Import table features
                'number_of_imports': self._count_imports(pe),
                'imported_dlls': self._get_imported_dlls(pe),
                'suspicious_imports': self._detect_suspicious_imports(pe),
                
                # Export table features
                'number_of_exports': len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
                
                # Resource features
                'has_resources': hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'),
                'number_of_resources': self._count_resources(pe),
                
                # Timestamp
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                
                # Hash
                'sha256': self._calculate_sha256(file_path),
            }
            
            pe.close()
            return features
            
        except pefile.PEFormatError as e:
            print(f"✗ Invalid PE file {file_path}: {e}")
            return None
        except Exception as e:
            print(f"✗ Error analyzing {file_path}: {e}")
            return None
    
    def _calculate_section_entropy(self, pe) -> Dict[str, float]:
        """Calculate entropy for each section"""
        section_entropy = {}
        if self.max_scan_bytes is not None:
            return section_entropy
        for section in pe.sections:
            section_name = section.Name.decode().strip('\x00')
            entropy = section.get_entropy()
            section_entropy[section_name] = round(entropy, 2)
        return section_entropy
    
    def _calculate_total_entropy(self, file_path: str) -> float:
        """Calculate entropy of entire file"""
        # Calculate byte frequency
        byte_counts = Counter()
        data_len = 0
        with open(file_path, 'rb') as f:
            while self.max_scan_bytes is None or data_len < self.max_scan_bytes:
                read_size = self.ENTROPY_CHUNK_BYTES
                if self.max_scan_bytes is not None:
                    read_size = min(read_size, self.max_scan_bytes - data_len)
                chunk = f.read(read_size)
                if not chunk:
                    break
                byte_counts.update(chunk)
                data_len += len(chunk)

        if not data_len:
            return 0.0

        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            freq = count / data_len
            entropy -= freq * math.log2(freq)
        
        return round(entropy, 2)
    
    def _count_imports(self, pe) -> int:
        """Count total number of imported functions"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return 0
        
        count = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            count += len(entry.imports)
        return count
    
    def _get_imported_dlls(self, pe) -> list:
        """Get list of imported DLLs"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return []
        
        return [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
    
    def _detect_suspicious_imports(self, pe) -> list:
        """Detect suspicious API calls commonly used by malware"""
        suspicious_apis = [
            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'InternetOpen',
            'URLDownloadToFile', 'WinExec', 'ShellExecute',
            'CreateProcess', 'RegSetValue', 'CryptAcquireContext'
        ]
        
        found_suspicious = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return found_suspicious
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode()
                    if any(api in func_name for api in suspicious_apis):
                        found_suspicious.append(func_name)
        
        return found_suspicious
    
    def _count_resources(self, pe) -> int:
        """Count number of resources"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return 0
        
        count = 0
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                count += len(resource_type.directory.entries)
        return count
    
    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


if __name__ == "__main__":
    # Test the analyzer
    analyzer = PEAnalyzer()
    
    # Example: analyze a sample file
    sample_path = "data_collection/raw_samples/malicious/sample.exe"
    features = analyzer.analyze_file(sample_path)
    
    if features:
        print("\n=== PE Analysis Results ===")
        for key, value in features.items():
            print(f"{key}: {value}")
