"""
配置管理模块 - 管理各类API密钥和平台配置
支持：Fofa、Shodan、Hunter等空间测绘平台
"""

import os
import json

class ConfigManager:
    def __init__(self):
        """初始化配置管理器"""
        self.config_file = "config.json"
        self.default_config = {
            "fofa": {
                "enabled": False,
                "email": "",
                "key": ""
            },
            "shodan": {
                "enabled": False,
                "api_key": ""
            },
            "hunter": {
                "enabled": False,
                "api_key": ""
            },
            "zoomeye": {
                "enabled": False,
                "username": "",
                "password": ""
            },
            "scan": {
                "timeout": 30,
                "threads": 10,
                "max_results": 100
            }
        }
    
    def load_config(self) -> dict:
        """加载配置文件"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return self.default_config
        return self.default_config
    
    def save_config(self, config: dict):
        """保存配置文件"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    
    def get_platforms(self) -> list:
        """获取支持的平台列表"""
        return ["fofa", "shodan", "hunter", "zoomeye"]
    
    def get_platform_info(self, platform: str) -> dict:
        """获取平台信息"""
        info = {
            "fofa": {
                "name": "FOFA",
                "description": "FOFA网络空间测绘系统",
                "url": "https://fofa.so",
                "required_fields": ["email", "key"]
            },
            "shodan": {
                "name": "Shodan",
                "description": "Shodan搜索引擎",
                "url": "https://shodan.io",
                "required_fields": ["api_key"]
            },
            "hunter": {
                "name": "Hunter",
                "description": "Hunter网络空间搜索引擎",
                "url": "https://hunter.qianxin.com",
                "required_fields": ["api_key"]
            },
            "zoomeye": {
                "name": "ZoomEye",
                "description": "ZoomEye网络空间搜索引擎",
                "url": "https://www.zoomeye.org",
                "required_fields": ["username", "password"]
            }
        }
        return info.get(platform, {})