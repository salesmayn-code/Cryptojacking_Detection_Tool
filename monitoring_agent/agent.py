"""
System Monitoring Agent - Collects real-time metrics
"""
import psutil
import time
import requests
import json
from datetime import datetime
from typing import Dict, List
import os
from dotenv import load_dotenv

load_dotenv()


class SystemMonitoringAgent:
    def __init__(self, system_id: str, api_url: str = None):
        self.system_id = system_id
        self.api_url = api_url or os.getenv('API_URL', 'http://localhost:8000')
        self.update_interval = int(os.getenv('AGENT_UPDATE_INTERVAL', 5))  # seconds
        self.is_running = False
        self.metrics_buffer = []
        
    def collect_cpu_metrics(self) -> Dict:
        """Collect CPU usage metrics"""
        cpu_percent = psutil.cpu_percent(interval=1, percpu=False)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        return {
            'cpu_percent': cpu_percent,
            'cpu_count': cpu_count,
            'cpu_freq_current': cpu_freq.current if cpu_freq else 0,
            'cpu_freq_max': cpu_freq.max if cpu_freq else 0
        }
    
    def collect_memory_metrics(self) -> Dict:
        """Collect memory usage metrics"""
        memory = psutil.virtual_memory()
        
        return {
            'memory_total': memory.total,
            'memory_available': memory.available,
            'memory_used': memory.used,
            'memory_percent': memory.percent
        }
    
    def collect_network_metrics(self) -> Dict:
        """Collect network I/O metrics"""
        net_io = psutil.net_io_counters()
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    
    def collect_process_metrics(self) -> List[Dict]:
        """Collect process information"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                # Only include processes using significant resources
                if pinfo['cpu_percent'] > 5 or pinfo['memory_percent'] > 5:
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu_percent': pinfo['cpu_percent'],
                        'memory_percent': pinfo['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return processes[:10]  # Top 10 processes
    
    def collect_all_metrics(self) -> Dict:
        """Collect all system metrics"""
        timestamp = datetime.now().isoformat()
        
        metrics = {
            'system_id': self.system_id,
            'timestamp': timestamp,
            'cpu': self.collect_cpu_metrics(),
            'memory': self.collect_memory_metrics(),
            'network': self.collect_network_metrics(),
            'top_processes': self.collect_process_metrics()
        }
        
        return metrics
    
    def send_metrics_to_server(self, metrics: Dict) -> bool:
        """
        Send collected metrics to backend server
        
        Args:
            metrics: Dictionary of collected metrics
            
        Returns:
            True if successful, False otherwise
        """
        try:
            response = requests.post(
                f"{self.api_url}/api/metrics",
                json=metrics,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Check if cryptojacking detected
                if result.get('alert'):
                    self.handle_alert(result['alert'])
                
                return True
            else:
                print(f"ERROR: server returned status {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"ERROR sending metrics: {e}")
            # Buffer metrics for retry
            self.metrics_buffer.append(metrics)
            return False
    
    def handle_alert(self, alert: Dict):
        """
        Handle cryptojacking detection alert
        
        Args:
            alert: Alert information from server
        """
        print("\n" + "="*50)
        print("WARNING: CRYPTOJACKING ALERT DETECTED")
        print("="*50)
        print(f"Timestamp: {alert.get('timestamp')}")
        print(f"Confidence: {alert.get('confidence', 0):.2%}")
        print(f"CPU Usage: {alert.get('metrics', {}).get('cpu_usage', 0):.1f}%")
        print(f"Memory Usage: {alert.get('metrics', {}).get('memory_usage', 0):.1f}%")
        
        if alert.get('suspicious_processes'):
            print("\nSuspicious Processes:")
            for proc in alert['suspicious_processes']:
                print(f"  - {proc}")
        print("="*50 + "\n")
    
    def retry_buffered_metrics(self):
        """Retry sending buffered metrics"""
        if not self.metrics_buffer:
            return
        
        print(f"Retrying {len(self.metrics_buffer)} buffered metrics...")
        successful = []
        
        for metrics in self.metrics_buffer:
            if self.send_metrics_to_server(metrics):
                successful.append(metrics)
        
        # Remove successfully sent metrics
        for metrics in successful:
            self.metrics_buffer.remove(metrics)
    
    def start(self):
        """Start monitoring agent"""
        self.is_running = True
        print(f"\nMonitoring Agent Started")
        print(f"  System ID: {self.system_id}")
        print(f"  API URL: {self.api_url}")
        print(f"  Update Interval: {self.update_interval}s")
        print(f"\nCollecting metrics...\n")
        
        iteration = 0
        
        try:
            while self.is_running:
                iteration += 1
                
                # Collect metrics
                metrics = self.collect_all_metrics()
                
                # Display current status
                print(f"[{iteration}] {datetime.now().strftime('%H:%M:%S')} - "
                      f"CPU: {metrics['cpu']['cpu_percent']:.1f}% | "
                      f"Memory: {metrics['memory']['memory_percent']:.1f}% | "
                      f"Processes: {len(metrics['top_processes'])}")
                
                # Send to server
                self.send_metrics_to_server(metrics)
                
                # Retry buffered metrics periodically
                if iteration % 10 == 0:
                    self.retry_buffered_metrics()
                
                # Wait for next interval
                time.sleep(self.update_interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring Agent Stopped")
            self.is_running = False
    
    def stop(self):
        """Stop monitoring agent"""
        self.is_running = False


if __name__ == "__main__":
    # Create and start monitoring agent
    import sys
    
    system_id = sys.argv[1] if len(sys.argv) > 1 else "SYSTEM-001"
    
    agent = SystemMonitoringAgent(system_id=system_id)
    agent.start()
