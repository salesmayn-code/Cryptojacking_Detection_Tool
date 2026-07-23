"""API clients for malware sample collection"""
from .virustotal_client import VirusTotalClient
from .malwarebazaar_client import MalwareBazaarClient

__all__ = ['VirusTotalClient', 'MalwareBazaarClient']
