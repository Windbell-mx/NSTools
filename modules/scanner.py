"""
扫描器模块 - 负责执行各类扫描任务和数据处理流程
数据流转：收集 → 验证 → 清洗 → 存储 → 展示
"""

import subprocess
import re
import socket
import requests
import dns.resolver
import asyncio
import aiohttp
import whois
import ssl
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin

class DataProcessor:
    """数据处理器 - 负责数据清洗、验证和去重"""
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """验证域名格式"""
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """验证IP地址格式"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    @staticmethod
    def deduplicate_subdomains(subdomains: List[Dict]) -> List[Dict]:
        """子域名去重"""
        seen = set()
        result = []
        for sub in subdomains:
            domain = sub.get('域名', '')
            if domain and domain not in seen:
                seen.add(domain)
                result.append(sub)
        return result
    
    @staticmethod
    def deduplicate_ports(ports: List[Dict]) -> List[Dict]:
        """端口去重"""
        seen = set()
        result = []
        for port in ports:
            key = f"{port.get('IP地址', '')}:{port.get('端口', '')}"
            if key not in seen:
                seen.add(key)
                result.append(port)
        return result
    
    @staticmethod
    def deduplicate_directories(directories: List[Dict]) -> List[Dict]:
        """目录去重"""
        seen = set()
        result = []
        for d in directories:
            url = d.get('URL', '')
            if url not in seen:
                seen.add(url)
                result.append(d)
        return result
    
    @staticmethod
    def clean_fingerprints(fingerprints: List[Dict]) -> List[Dict]:
        """清洗指纹数据"""
        seen = set()
        result = []
        for fp in fingerprints:
            key = f"{fp.get('目标', '')}_{fp.get('技术', '')}"
            if key not in seen:
                seen.add(key)
                result.append(fp)
        return result
    
    @staticmethod
    def validate_services(results: Dict) -> Dict:
        """验证所有服务的可用性"""
        # 验证子域名
        for sub in results.get('subdomains', []):
            if sub.get('IP地址') == '解析失败':
                sub['状态'] = '待验证'
            else:
                sub['状态'] = '有效'
        
        # 验证端口
        for port in results.get('ports', []):
            if port.get('状态') == '开放':
                port['状态'] = '开放'
            else:
                port['状态'] = '关闭'
        
        return results

class Scanner:
    def __init__(self, target: str, options: dict):
        """初始化扫描器"""
        self.target = target                    # 扫描目标
        self.options = options                  # 扫描选项
        self.processed_results = None           # 处理后的结果
        
        # 初始化结果结构
        self.raw_results = {
            'dns': {},                          # DNS信息
            'whois': {},                        # WHOIS信息
            'subdomains': [],                   # 子域名结果
            'ports': [],                         # 端口扫描结果
            'directories': [],                  # 目录扫描结果
            'sensitive_files': [],               # 敏感文件
            'fingerprints': [],                 # 指纹识别结果
            'ssl': {},                          # SSL证书信息
            'waf': [],                          # WAF识别
            'cdn': [],                          # CDN识别
            'cloud': [],                        # 云服务识别
            'icp': {}                           # 备案信息
        }
        
        # 常用端口列表
        self.common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3306, 3389, 5432]
        
        # 常用目录列表
        self.common_directories = [
            '/admin', '/login', '/api', '/api/v1', '/robots.txt',
            '/sitemap.xml', '/.git', '/.env', '/backup', '/download',
            '/config', '/logs', '/db', '/database', '/admin.php',
            '/phpinfo.php', '/info.php', '/test.php', '/backup.zip',
            '/backup.tar.gz', '/www.zip', '/web.zip', '/index.bak'
        ]
        
        # 敏感文件路径
        self.sensitive_paths = [
            '/.env', '/.git/config', '/.git/HEAD', '/backup.sql',
            '/dump.sql', '/mysql.sql', '/db.sql', '/config.php',
            '/wp-config.php', '/config.inc.php', '/.htaccess',
            '/server-status', '/phpmyadmin', '/phpMyAdmin',
            '/adminer', '/shell.php', '/cmd.php', '/webshell.php'
        ]

    def run(self) -> Dict:
        """执行完整的数据处理流程"""
        # Phase 1: 数据收集
        self.collect_data()
        
        # Phase 2: 数据处理（验证、清洗、去重）
        self.process_data()
        
        return self.processed_results

    def collect_data(self):
        """数据收集阶段"""
        if self.options.get('dns', False):
            self.raw_results['dns'] = self.collect_dns_info()
        
        if self.options.get('whois', False):
            self.raw_results['whois'] = self.collect_whois_info()
        
        if self.options.get('subdomain', False):
            self.raw_results['subdomains'] = self.discover_subdomains()
        
        if self.options.get('port', False):
            self.raw_results['ports'] = self.scan_ports()
        
        if self.options.get('directory', False):
            self.raw_results['directories'] = self.scan_directories()
        
        if self.options.get('sensitive', False):
            self.raw_results['sensitive_files'] = self.scan_sensitive_files()
        
        if self.options.get('fingerprint', False):
            self.raw_results['fingerprints'] = self.identify_fingerprints()
        
        if self.options.get('ssl', False):
            self.raw_results['ssl'] = self.collect_ssl_info()
        
        if self.options.get('waf', False):
            self.raw_results['waf'] = self.detect_waf()
        
        if self.options.get('cdn', False):
            self.raw_results['cdn'] = self.detect_cdn()
        
        if self.options.get('cloud', False):
            self.raw_results['cloud'] = self.detect_cloud()
        
        if self.options.get('icp', False):
            self.raw_results['icp'] = self.query_icp_info()

    def process_data(self):
        """数据处理阶段：验证 → 清洗 → 去重"""
        processor = DataProcessor()
        
        # 验证数据
        validated = processor.validate_services(self.raw_results)
        
        # 去重处理
        validated['subdomains'] = processor.deduplicate_subdomains(validated.get('subdomains', []))
        validated['ports'] = processor.deduplicate_ports(validated.get('ports', []))
        validated['directories'] = processor.deduplicate_directories(validated.get('directories', []))
        validated['fingerprints'] = processor.clean_fingerprints(validated.get('fingerprints', []))
        
        # 统计信息
        validated['summary'] = {
            'total_subdomains': len(validated['subdomains']),
            'total_ports': len(validated['ports']),
            'total_directories': len(validated['directories']),
            'total_fingerprints': len(validated['fingerprints']),
            'total_sensitive_files': len(validated['sensitive_files']),
            'valid_subdomains': sum(1 for s in validated['subdomains'] if s.get('状态') == '有效'),
            'open_ports': sum(1 for p in validated['ports'] if p.get('状态') == '开放')
        }
        
        self.processed_results = validated

    def collect_dns_info(self) -> Dict:
        """收集DNS记录信息"""
        info = {}
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            info['A记录'] = [str(rdata) for rdata in answers]
        except:
            info['A记录'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'AAAA')
            info['AAAA记录'] = [str(rdata) for rdata in answers]
        except:
            info['AAAA记录'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'MX')
            info['MX记录'] = [str(rdata.exchange) for rdata in answers]
        except:
            info['MX记录'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'NS')
            info['NS记录'] = [str(rdata) for rdata in answers]
        except:
            info['NS记录'] = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'TXT')
            info['TXT记录'] = [str(rdata) for rdata in answers]
        except:
            info['TXT记录'] = []
        
        return info

    def collect_whois_info(self) -> Dict:
        """收集WHOIS信息"""
        info = {}
        try:
            w = whois.whois(self.target)
            info['域名'] = w.domain_name
            info['注册商'] = w.registrar
            info['注册人'] = w.name
            info['注册邮箱'] = w.email
            info['注册时间'] = str(w.creation_date) if w.creation_date else ''
            info['到期时间'] = str(w.expiration_date) if w.expiration_date else ''
            info['更新时间'] = str(w.updated_date) if w.updated_date else ''
            info['状态'] = w.status
            info['DNS服务器'] = w.name_servers
        except Exception as e:
            info['错误'] = str(e)
        return info

    def is_tool_available(self, tool_name: str) -> bool:
        """检查工具是否已安装"""
        try:
            result = subprocess.run(
                [tool_name, '--version'],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
        except:
            return False

    def run_subfinder(self) -> List[str]:
        """运行subfinder工具收集子域名"""
        subdomains = []
        if not self.is_tool_available('subfinder'):
            return subdomains
        
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.target, '-silent'],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and '.' in line:
                    subdomains.append(line)
        except Exception as e:
            pass
        
        return subdomains

    def run_amass(self) -> List[str]:
        """运行amass工具收集子域名"""
        subdomains = []
        if not self.is_tool_available('amass'):
            return subdomains
        
        try:
            result = subprocess.run(
                ['amass', 'enum', '-d', self.target, '-silent'],
                capture_output=True, text=True, timeout=180
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and '.' in line:
                    subdomains.append(line)
        except Exception as e:
            pass
        
        return subdomains

    def discover_subdomains(self) -> List[Dict]:
        """发现子域名 - 集成subfinder和amass工具"""
        subdomains = []
        discovered_domains = set()
        
        # 基础子域名枚举
        common_subdomains = [
            'www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev',
            'staging', 'mobile', 'cdn', 'blog', 'webmail', 'smtp',
            'pop', 'imap', 'ns1', 'ns2', 'dns', 'mx', 'vpn',
            'portal', 'dashboard', 'app', 'cloud', 's3', 'storage'
        ]
        
        for sub in common_subdomains:
            domain = f"{sub}.{self.target}"
            if domain not in discovered_domains:
                try:
                    ip = socket.gethostbyname(domain)
                    subdomains.append({
                        '域名': domain,
                        'IP地址': ip,
                        '状态': '有效',
                        '来源': '基础枚举'
                    })
                    discovered_domains.add(domain)
                except:
                    continue
        
        # 使用host命令
        try:
            result = subprocess.run(
                ['host', self.target],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                match = re.search(r'has address (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    if self.target not in discovered_domains:
                        subdomains.append({
                            '域名': self.target,
                            'IP地址': match.group(1),
                            '状态': '有效',
                            '来源': 'DNS解析'
                        })
                        discovered_domains.add(self.target)
        except:
            pass
        
        # 使用subfinder工具
        subfinder_results = self.run_subfinder()
        for domain in subfinder_results:
            if domain not in discovered_domains:
                try:
                    ip = socket.gethostbyname(domain)
                    subdomains.append({
                        '域名': domain,
                        'IP地址': ip,
                        '状态': '有效',
                        '来源': 'subfinder'
                    })
                    discovered_domains.add(domain)
                except:
                    subdomains.append({
                        '域名': domain,
                        'IP地址': '解析失败',
                        '状态': '待验证',
                        '来源': 'subfinder'
                    })
                    discovered_domains.add(domain)
        
        # 使用amass工具
        amass_results = self.run_amass()
        for domain in amass_results:
            if domain not in discovered_domains:
                try:
                    ip = socket.gethostbyname(domain)
                    subdomains.append({
                        '域名': domain,
                        'IP地址': ip,
                        '状态': '有效',
                        '来源': 'amass'
                    })
                    discovered_domains.add(domain)
                except:
                    subdomains.append({
                        '域名': domain,
                        'IP地址': '解析失败',
                        '状态': '待验证',
                        '来源': 'amass'
                    })
                    discovered_domains.add(domain)
        
        return subdomains

    def scan_ports(self) -> List[Dict]:
        """扫描端口"""
        ports = []
        target_ips = self.raw_results['dns'].get('A记录', [])
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
                            'IP地址': ip,
                            '端口': port,
                            '服务': service,
                            '状态': '开放',
                            '协议': 'TCP'
                        })
                except:
                    continue
        
        return ports

    def get_service_name(self, port: int) -> str:
        """获取端口对应的服务名称"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP',
            8443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        return services.get(port, '未知')

    def scan_directories(self) -> List[Dict]:
        """扫描Web目录"""
        directories = []
        base_url = f"http://{self.target}"
        
        async def check_directory(session, path):
            url = urljoin(base_url, path)
            try:
                async with session.get(url, timeout=10) as response:
                    if response.status in [200, 301, 302, 403]:
                        return {
                            'URL': url,
                            '状态码': response.status,
                            '内容类型': response.headers.get('Content-Type', ''),
                            '大小': response.headers.get('Content-Length', 0)
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
                            'URL': url,
                            '状态码': response.status,
                            '内容类型': response.headers.get('Content-Type', ''),
                            '大小': response.headers.get('Content-Length', 0)
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

    def scan_sensitive_files(self) -> List[Dict]:
        """扫描敏感文件"""
        sensitive_files = []
        base_url = f"http://{self.target}"
        
        async def check_file(session, path):
            url = urljoin(base_url, path)
            try:
                async with session.get(url, timeout=10) as response:
                    if response.status in [200, 403]:
                        return {
                            'URL': url,
                            '状态码': response.status,
                            '文件类型': path.split('/')[-1] if path else ''
                        }
            except:
                return None
            return None
        
        async def main():
            async with aiohttp.ClientSession() as session:
                tasks = [check_file(session, path) for path in self.sensitive_paths]
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        sensitive_files.append(result)
        
        try:
            asyncio.run(main())
        except:
            pass
        
        return sensitive_files

    def collect_ssl_info(self) -> Dict:
        """收集SSL证书信息"""
        info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as secure_sock:
                    cert = secure_sock.getpeercert()
                    info['颁发机构'] = cert.get('issuer', [])[-1][0][1] if cert.get('issuer') else ''
                    info['有效期开始'] = cert.get('notBefore', '')
                    info['有效期结束'] = cert.get('notAfter', '')
                    info['加密算法'] = cert.get('cipher', '')
                    info['证书版本'] = cert.get('version', '')
                    info['序列号'] = cert.get('serialNumber', '')
                    info['主体名称'] = cert.get('subject', [])[-1][0][1] if cert.get('subject') else ''
        except Exception as e:
            info['错误'] = str(e)
        return info

    def identify_fingerprints(self) -> List[Dict]:
        """识别技术指纹"""
        fingerprints = []
        urls = [f"http://{self.target}", f"https://{self.target}"]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                
                server = response.headers.get('Server', '')
                if server:
                    fingerprints.append({
                        '目标': url,
                        '技术': '服务器',
                        '版本': server
                    })
                
                x_powered_by = response.headers.get('X-Powered-By', '')
                if x_powered_by:
                    fingerprints.append({
                        '目标': url,
                        '技术': '开发框架',
                        '版本': x_powered_by
                    })
                
                if 'wp-content' in response.text or 'wordpress' in response.text.lower():
                    fingerprints.append({
                        '目标': url,
                        '技术': 'WordPress',
                        '版本': '未知'
                    })
                
                if 'Drupal' in response.text:
                    fingerprints.append({
                        '目标': url,
                        '技术': 'Drupal',
                        '版本': '未知'
                    })
                
                if 'Joomla' in response.text:
                    fingerprints.append({
                        '目标': url,
                        '技术': 'Joomla',
                        '版本': '未知'
                    })
                
                if 'nginx' in response.headers.get('Server', '').lower():
                    version = re.search(r'nginx/([\d.]+)', response.headers.get('Server', ''))
                    fingerprints.append({
                        '目标': url,
                        '技术': 'Nginx',
                        '版本': version.group(1) if version else '未知'
                    })
                
                if 'Apache' in response.headers.get('Server', ''):
                    version = re.search(r'Apache/([\d.]+)', response.headers.get('Server', ''))
                    fingerprints.append({
                        '目标': url,
                        '技术': 'Apache',
                        '版本': version.group(1) if version else '未知'
                    })
            except:
                continue
        
        return fingerprints

    def detect_waf(self) -> List[Dict]:
        """检测WAF"""
        waf_list = []
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'Akamai': ['akamai'],
            'AWS WAF': ['x-amz-cf-id'],
            '阿里云WAF': ['aliyun'],
            '百度云WAF': ['baidu'],
            '腾讯云WAF': ['tencent']
        }
        
        try:
            response = requests.get(f"https://{self.target}", timeout=10, verify=False)
            headers = response.headers
            
            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in str(headers).lower() or signature.lower() in response.text.lower():
                        waf_list.append({
                            '名称': waf_name,
                            '检测位置': 'headers' if signature.lower() in str(headers).lower() else 'body'
                        })
                        break
        except:
            pass
        
        return waf_list

    def detect_cdn(self) -> List[Dict]:
        """检测CDN"""
        cdn_list = []
        cdn_signatures = {
            'Cloudflare': ['cloudflare', 'cf-'],
            '阿里云CDN': ['alidns', 'aliyun'],
            '腾讯云CDN': ['qcloud', 'tencent'],
            '百度云加速': ['baidu', 'bce'],
            'Fastly': ['fastly'],
            'Akamai': ['akamai']
        }
        
        try:
            ip = socket.gethostbyname(self.target)
            response = requests.get(f"https://{self.target}", timeout=10, verify=False)
            headers = response.headers
            
            for cdn_name, signatures in cdn_signatures.items():
                for signature in signatures:
                    if signature.lower() in str(headers).lower() or signature.lower() in response.text.lower():
                        cdn_list.append({
                            '名称': cdn_name,
                            'IP地址': ip
                        })
                        break
        except:
            pass
        
        return cdn_list

    def detect_cloud(self) -> List[Dict]:
        """检测云服务"""
        cloud_list = []
        cloud_ips = {
            'AWS': ['52.', '54.', '35.', '34.', '3.', '18.'],
            'Azure': ['40.', '13.', '104.', '10.'],
            'GCP': ['35.', '34.', '104.', '142.', '23.'],
            '阿里云': ['47.', '120.', '118.', '139.'],
            '腾讯云': ['106.', '119.', '129.', '134.']
        }
        
        try:
            ip = socket.gethostbyname(self.target)
            for cloud_name, prefixes in cloud_ips.items():
                for prefix in prefixes:
                    if ip.startswith(prefix):
                        cloud_list.append({
                            '名称': cloud_name,
                            'IP地址': ip
                        })
                        break
        except:
            pass
        
        return cloud_list

    def query_icp_info(self) -> Dict:
        """查询ICP备案信息"""
        info = {}
        try:
            response = requests.get(
                f"https://icp.chinaz.com/home/info?domain={self.target}",
                timeout=30
            )
            if response.status_code == 200:
                match = re.search(r'<span class="fz14">(.*?)</span>', response.text)
                if match:
                    info['备案号'] = match.group(1)
                
                match = re.search(r'<td>主办单位名称</td><td>(.*?)</td>', response.text)
                if match:
                    info['主办单位'] = match.group(1)
                
                match = re.search(r'<td>网站名称</td><td>(.*?)</td>', response.text)
                if match:
                    info['网站名称'] = match.group(1)
        except Exception as e:
            info['错误'] = str(e)
        
        if not info:
            info['提示'] = '请手动访问 https://icp.chinaz.com 查询备案信息'
        
        return info