import subprocess
import re
import socket
import requests
import dns.resolver
import asyncio
import aiohttp
from typing import List, Dict, Optional
from urllib.parse import urljoin

class Scanner:
    def __init__(self, target: str, options: dict):
        self.target = target
        self.options = options
        self.results = {
            'subdomains': [],
            'ports': [],
            'directories': [],
            'fingerprints': [],
            'dns': {}
        }
        
        self.common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3306, 3389, 5432]
        self.common_directories = [
            '/admin', '/login', '/api', '/api/v1', '/robots.txt',
            '/sitemap.xml', '/.git', '/.env', '/backup', '/download'
        ]

    def run(self) -> Dict:
        if self.options.get('dns', False):
            self.results['dns'] = self.collect_dns_info()
        
        if self.options.get('subdomain', False):
            self.results['subdomains'] = self.discover_subdomains()
        
        if self.options.get('port', False):
            self.results['ports'] = self.scan_ports()
        
        if self.options.get('directory', False):
            self.results['directories'] = self.scan_directories()
        
        if self.options.get('fingerprint', False):
            self.results['fingerprints'] = self.identify_fingerprints()
        
        return self.results

    def collect_dns_info(self) -> Dict:
        info = {}
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            info['A_records'] = [str(rdata) for rdata in answers]
        except:
            info['A_records'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'AAAA')
            info['AAAA_records'] = [str(rdata) for rdata in answers]
        except:
            info['AAAA_records'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'MX')
            info['MX_records'] = [str(rdata.exchange) for rdata in answers]
        except:
            info['MX_records'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'NS')
            info['NS_records'] = [str(rdata) for rdata in answers]
        except:
            info['NS_records'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'TXT')
            info['TXT_records'] = [str(rdata) for rdata in answers]
        except:
            info['TXT_records'] = []
        
        return info

    def discover_subdomains(self) -> List[Dict]:
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev',
            'staging', 'mobile', 'cdn', 'blog', 'webmail', 'smtp'
        ]
        
        for sub in common_subdomains:
            domain = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(domain)
                subdomains.append({
                    'domain': domain,
                    'ip': ip,
                    'status': 'valid'
                })
            except:
                continue
        
        try:
            result = subprocess.run(
                ['host', self.target],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                match = re.search(r'has address (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    subdomains.append({
                        'domain': self.target,
                        'ip': match.group(1),
                        'status': 'valid'
                    })
        except:
            pass
        
        return subdomains

    def scan_ports(self) -> List[Dict]:
        ports = []
        target_ips = self.results['dns'].get('A_records', [])
        if not target_ips and self.target.replace('.', '').isdigit():
            target_ips = [self.target]
        if not target_ips:
            return ports
        
        for ip in target_ips[:2]:
            for port in self.common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        service = self.get_service_name(port)
                        ports.append({
                            'ip': ip,
                            'port': port,
                            'service': service,
                            'status': 'open',
                            'protocol': 'TCP'
                        })
                except:
                    continue
        
        return ports

    def get_service_name(self, port: int) -> str:
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP',
            8443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        return services.get(port, 'Unknown')

    def scan_directories(self) -> List[Dict]:
        directories = []
        base_url = f"http://{self.target}"
        
        async def check_directory(session, path):
            url = urljoin(base_url, path)
            try:
                async with session.get(url, timeout=10) as response:
                    if response.status in [200, 301, 302, 403]:
                        return {
                            'url': url,
                            'status_code': response.status,
                            'content_type': response.headers.get('Content-Type', ''),
                            'size': response.headers.get('Content-Length', 0)
                        }
            except:
                return None
            return None
        
        async def main():
            async with aiohttp.ClientSession() as session:
                tasks = [check_directory(session, path) for path in self.common_directories]
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        directories.append(result)
        
        try:
            asyncio.run(main())
        except:
            pass
        
        https_url = f"https://{self.target}"
        async def check_https_directory(session, path):
            url = urljoin(https_url, path)
            try:
                async with session.get(url, timeout=10, ssl=False) as response:
                    if response.status in [200, 301, 302, 403]:
                        return {
                            'url': url,
                            'status_code': response.status,
                            'content_type': response.headers.get('Content-Type', ''),
                            'size': response.headers.get('Content-Length', 0)
                        }
            except:
                return None
            return None
        
        async def https_main():
            async with aiohttp.ClientSession() as session:
                tasks = [check_https_directory(session, path) for path in self.common_directories]
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        directories.append(result)
        
        try:
            asyncio.run(https_main())
        except:
            pass
        
        return directories

    def identify_fingerprints(self) -> List[Dict]:
        fingerprints = []
        urls = [f"http://{self.target}", f"https://{self.target}"]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                
                server = response.headers.get('Server', '')
                if server:
                    fingerprints.append({
                        'target': url,
                        'technology': 'Server',
                        'version': server
                    })
                
                x_powered_by = response.headers.get('X-Powered-By', '')
                if x_powered_by:
                    fingerprints.append({
                        'target': url,
                        'technology': 'X-Powered-By',
                        'version': x_powered_by
                    })
                
                if 'wp-content' in response.text or 'wordpress' in response.text.lower():
                    fingerprints.append({
                        'target': url,
                        'technology': 'WordPress',
                        'version': 'Unknown'
                    })
                
                if 'Drupal' in response.text:
                    fingerprints.append({
                        'target': url,
                        'technology': 'Drupal',
                        'version': 'Unknown'
                    })
                
                if 'Joomla' in response.text:
                    fingerprints.append({
                        'target': url,
                        'technology': 'Joomla',
                        'version': 'Unknown'
                    })
                
                if 'nginx' in response.headers.get('Server', '').lower():
                    fingerprints.append({
                        'target': url,
                        'technology': 'Nginx',
                        'version': re.search(r'nginx/([\d.]+)', response.headers.get('Server', '')).group(1) if re.search(r'nginx/([\d.]+)', response.headers.get('Server', '')) else 'Unknown'
                    })
                
                if 'Apache' in response.headers.get('Server', ''):
                    fingerprints.append({
                        'target': url,
                        'technology': 'Apache',
                        'version': re.search(r'Apache/([\d.]+)', response.headers.get('Server', '')).group(1) if re.search(r'Apache/([\d.]+)', response.headers.get('Server', '')) else 'Unknown'
                    })
            except:
                continue
        
        return fingerprints