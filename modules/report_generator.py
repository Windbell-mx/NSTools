"""
报告生成器模块 - 负责生成扫描报告
功能：生成Markdown报告、CSV数据文件
"""

import os
import csv
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        """初始化报告生成器"""
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_report(self, results: dict, target: str) -> str:
        """生成完整报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"pentest_report_{target}_{timestamp}"
        
        # 生成Markdown报告
        md_content = self.generate_markdown(results, target)
        md_path = os.path.join(self.report_dir, f"{report_name}.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        # 生成CSV数据文件
        self.generate_csv_files(results, report_name)
        
        return md_path
    
    def generate_markdown(self, results: dict, target: str) -> str:
        """生成Markdown格式报告"""
        sections = []
        
        sections.append(f"# 渗透测试信息收集报告")
        sections.append(f"")
        sections.append(f"## 基本信息")
        sections.append(f"- **目标:** {target}")
        sections.append(f"- **生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sections.append(f"- **报告版本:** v1.0")
        sections.append(f"")
        
        # DNS信息
        if results.get('dns'):
            sections.append(f"## DNS信息")
            sections.append(f"")
            for record_type, records in results['dns'].items():
                if records:
                    sections.append(f"### {record_type}")
                    for record in records:
                        sections.append(f"- {record}")
                    sections.append(f"")
        
        # 子域名
        if results.get('subdomains'):
            sections.append(f"## 子域名发现")
            sections.append(f"")
            sections.append(f"| 域名 | IP地址 | 状态 |")
            sections.append(f"|------|--------|------|")
            for sub in results['subdomains']:
                sections.append(f"| {sub.get('域名', '')} | {sub.get('IP地址', '')} | {sub.get('状态', '')} |")
            sections.append(f"")
        
        # 端口
        if results.get('ports'):
            sections.append(f"## 端口扫描")
            sections.append(f"")
            sections.append(f"| IP地址 | 端口 | 服务 | 状态 | 协议 |")
            sections.append(f"|--------|------|------|------|------|")
            for port in results['ports']:
                sections.append(f"| {port.get('IP地址', '')} | {port.get('端口', '')} | {port.get('服务', '')} | {port.get('状态', '')} | {port.get('协议', '')} |")
            sections.append(f"")
        
        # 目录
        if results.get('directories'):
            sections.append(f"## 目录扫描")
            sections.append(f"")
            sections.append(f"| URL | 状态码 | 内容类型 | 大小 |")
            sections.append(f"|-----|--------|----------|------|")
            for dir_info in results['directories']:
                ct = dir_info.get('内容类型', '')[:30]
                sections.append(f"| {dir_info.get('URL', '')} | {dir_info.get('状态码', '')} | {ct} | {dir_info.get('大小', 0)} |")
            sections.append(f"")
        
        # 指纹
        if results.get('fingerprints'):
            sections.append(f"## 指纹识别")
            sections.append(f"")
            sections.append(f"| 目标 | 技术 | 版本 |")
            sections.append(f"|------|------|------|")
            for fp in results['fingerprints']:
                sections.append(f"| {fp.get('目标', '')} | {fp.get('技术', '')} | {fp.get('版本', '')} |")
            sections.append(f"")
        
        # 总结
        sections.append(f"## 总结")
        total_count = sum(len(v) for v in results.values() if isinstance(v, list))
        sections.append(f"- 共发现 **{total_count}** 条有效信息")
        
        return "\n".join(sections)
    
    def generate_csv_files(self, results: dict, report_name: str):
        """生成CSV数据文件"""
        if results.get('subdomains'):
            with open(os.path.join(self.report_dir, f"{report_name}_subdomains.csv"), 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['域名', 'IP地址', '状态'])
                writer.writeheader()
                writer.writerows(results['subdomains'])
        
        if results.get('ports'):
            with open(os.path.join(self.report_dir, f"{report_name}_ports.csv"), 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['IP地址', '端口', '服务', '状态', '协议'])
                writer.writeheader()
                writer.writerows(results['ports'])
        
        if results.get('directories'):
            with open(os.path.join(self.report_dir, f"{report_name}_directories.csv"), 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['URL', '状态码', '内容类型', '大小'])
                writer.writeheader()
                writer.writerows(results['directories'])
        
        if results.get('fingerprints'):
            with open(os.path.join(self.report_dir, f"{report_name}_fingerprints.csv"), 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['目标', '技术', '版本'])
                writer.writeheader()
                writer.writerows(results['fingerprints'])