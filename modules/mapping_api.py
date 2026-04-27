"""
测绘平台集成模块 - 集成各类网络空间测绘平台API
支持：Fofa、Shodan、Hunter、ZoomEye
"""

import requests
import base64

class FofaAPI:
    """FOFA API客户端"""
    
    def __init__(self, email: str, key: str):
        self.email = email
        self.key = key
        self.base_url = "https://fofa.so/api/v1"
    
    def search(self, query: str, page: int = 1, size: int = 100) -> dict:
        """搜索FOFA数据"""
        try:
            url = f"{self.base_url}/search/all"
            params = {
                "email": self.email,
                "key": self.key,
                "qbase64": base64.b64encode(query.encode('utf-8')).decode('utf-8'),
                "page": page,
                "size": size
            }
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_host_info(self, ip: str) -> dict:
        """获取主机信息"""
        try:
            url = f"{self.base_url}/host/{ip}"
            params = {
                "email": self.email,
                "key": self.key
            }
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

class ShodanAPI:
    """Shodan API客户端"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
    
    def search(self, query: str, page: int = 1) -> dict:
        """搜索Shodan数据"""
        try:
            url = f"{self.base_url}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": query,
                "page": page
            }
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_host(self, ip: str) -> dict:
        """获取主机详细信息"""
        try:
            url = f"{self.base_url}/shodan/host/{ip}"
            params = {"key": self.api_key}
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

class HunterAPI:
    """Hunter API客户端"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://hunter.qianxin.com/openApi"
    
    def search(self, query: str, page: int = 1, size: int = 100) -> dict:
        """搜索Hunter数据"""
        try:
            url = f"{self.base_url}/search"
            params = {
                "api-key": self.api_key,
                "search": query,
                "page": page,
                "page_size": size
            }
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def get_ip_info(self, ip: str) -> dict:
        """获取IP信息"""
        try:
            url = f"{self.base_url}/ip"
            params = {
                "api-key": self.api_key,
                "ip": ip
            }
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

class ZoomEyeAPI:
    """ZoomEye API客户端"""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.base_url = "https://api.zoomeye.org"
        self.token = None
        self.login()
    
    def login(self):
        """登录获取token"""
        try:
            url = f"{self.base_url}/user/login"
            data = {
                "username": self.username,
                "password": self.password
            }
            response = requests.post(url, json=data, timeout=30)
            result = response.json()
            self.token = result.get("access_token")
        except Exception as e:
            pass
    
    def search(self, query: str, page: int = 1) -> dict:
        """搜索ZoomEye数据"""
        if not self.token:
            return {"error": "未登录"}
        
        try:
            url = f"{self.base_url}/search"
            headers = {"Authorization": f"JWT {self.token}"}
            params = {
                "query": query,
                "page": page
            }
            response = requests.get(url, headers=headers, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

class MappingScanner:
    """测绘平台扫描器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.clients = {}
        
        # 初始化各平台客户端
        if config.get('fofa', {}).get('enabled'):
            fofa_config = config['fofa']
            self.clients['fofa'] = FofaAPI(fofa_config['email'], fofa_config['key'])
        
        if config.get('shodan', {}).get('enabled'):
            self.clients['shodan'] = ShodanAPI(config['shodan']['api_key'])
        
        if config.get('hunter', {}).get('enabled'):
            self.clients['hunter'] = HunterAPI(config['hunter']['api_key'])
        
        if config.get('zoomeye', {}).get('enabled'):
            zoom_config = config['zoomeye']
            self.clients['zoomeye'] = ZoomEyeAPI(zoom_config['username'], zoom_config['password'])
    
    def search(self, query: str) -> dict:
        """在所有启用的平台中搜索"""
        results = {}
        
        for platform, client in self.clients.items():
            try:
                if platform == 'fofa':
                    data = client.search(query)
                elif platform == 'shodan':
                    data = client.search(query)
                elif platform == 'hunter':
                    data = client.search(query)
                elif platform == 'zoomeye':
                    data = client.search(query)
                
                if data and 'error' not in data:
                    results[platform] = data
            except Exception as e:
                results[platform] = {"error": str(e)}
        
        return results
    
    def get_enabled_platforms(self) -> list:
        """获取已启用的平台列表"""
        return list(self.clients.keys())