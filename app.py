import streamlit as st
import json
import uuid
import os
from datetime import datetime
from modules.scanner import Scanner
from modules.report_generator import ReportGenerator

st.set_page_config(
    page_title="渗透测试信息收集平台",
    page_icon="�️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E88E5;
        text-align: center;
        padding: 1rem 0;
        border-bottom: 2px solid #E3F2FD;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .stMetric {
        background: transparent !important;
    }
    .success-box {
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #4CAF50;
        background: #E8F5E9;
    }
</style>
""", unsafe_allow_html=True)

if 'tasks' not in st.session_state:
    st.session_state.tasks = []

if 'current_task' not in st.session_state:
    st.session_state.current_task = None

if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}

class TaskManager:
    @staticmethod
    def create_task(target: str, scan_options: dict) -> dict:
        task = {
            'id': str(uuid.uuid4())[:8],
            'target': target,
            'options': scan_options,
            'status': 'pending',
            'progress': 0,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        st.session_state.tasks.append(task)
        return task

    @staticmethod
    def update_task(task_id: str, updates: dict):
        for task in st.session_state.tasks:
            if task['id'] == task_id:
                task.update(updates)
                task['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                break

    @staticmethod
    def get_task(task_id: str) -> dict:
        for task in st.session_state.tasks:
            if task['id'] == task_id:
                return task
        return None

    @staticmethod
    def delete_task(task_id: str):
        st.session_state.tasks = [t for t in st.session_state.tasks if t['id'] != task_id]
        if task_id in st.session_state.scan_results:
            del st.session_state.scan_results[task_id]

def show_dashboard():
    st.markdown('<h1 class="main-header">�️ 渗透测试信息收集平台</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <p style="font-size: 1.1rem; color: #666;">
            自动化信息收集平台，支持域名枚举、子域名发现、端口扫描、目录探测、指纹识别等功能
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    total = len(st.session_state.tasks)
    completed = sum(1 for t in st.session_state.tasks if t['status'] == 'completed')
    running = sum(1 for t in st.session_state.tasks if t['status'] == 'running')
    pending = sum(1 for t in st.session_state.tasks if t['status'] == 'pending')
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>📊 总任务数</h3>
            <h1 style="font-size: 3rem; margin: 0;">{}</h1>
        </div>
        """.format(total), unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card" style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);">
            <h3>✅ 已完成</h3>
            <h1 style="font-size: 3rem; margin: 0;">{}</h1>
        </div>
        """.format(completed), unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
            <h3>⏳ 运行中</h3>
            <h1 style="font-size: 3rem; margin: 0;">{}</h1>
        </div>
        """.format(running), unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <h3>📋 等待中</h3>
            <h1 style="font-size: 3rem; margin: 0;">{}</h1>
        </div>
        """.format(pending), unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🔧 平台功能")
        st.markdown("""
        - **子域名扫描**: 自动发现目标域名的子域名
        - **端口扫描**: 检测目标IP的开放端口
        - **目录扫描**: 探测Web目录和敏感文件
        - **指纹识别**: 识别Web服务器和技术栈
        - **DNS收集**: 获取DNS记录信息
        - **报告生成**: 一键导出扫描报告
        """)
    
    with col2:
        st.subheader("⚡ 快速开始")
        st.info("在左侧菜单选择「创建任务」，输入目标域名即可开始扫描")

def show_task_creation():
    st.markdown('<h2 style="color: #1E88E5;">📝 创建扫描任务</h2>', unsafe_allow_html=True)
    
    with st.container():
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("### 🎯 扫描目标")
            target = st.text_input(
                "目标域名/IP",
                placeholder="例如: example.com",
                help="输入要扫描的域名或IP地址"
            )
        
        with col2:
            st.markdown("### ⏱️ 超时设置")
            timeout = st.slider(
                "请求超时时间（秒）",
                min_value=10,
                max_value=120,
                value=30,
                help="设置单个请求的超时时间"
            )
    
    st.markdown("---")
    st.markdown("### 🔍 选择扫描模块")
    
    col1, col2, col3 = st.columns(3)
    
    scan_options = {}
    
    with col1:
        with st.container():
            st.markdown("#### 🌐 信息收集")
            scan_options['dns'] = st.checkbox("DNS信息收集", value=True)
            scan_options['subdomain'] = st.checkbox("子域名扫描", value=True)
    
    with col2:
        with st.container():
            st.markdown("#### 🔎 服务扫描")
            scan_options['port'] = st.checkbox("端口扫描", value=True)
            scan_options['fingerprint'] = st.checkbox("指纹识别", value=True)
    
    with col3:
        with st.container():
            st.markdown("#### 📁 Web探测")
            scan_options['directory'] = st.checkbox("目录扫描", value=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        selected_count = sum([
            scan_options.get('dns', False),
            scan_options.get('subdomain', False),
            scan_options.get('port', False),
            scan_options.get('fingerprint', False),
            scan_options.get('directory', False)
        ])
        st.metric("已选模块", f"{selected_count} 个")
    
    with col2:
        if st.button("🚀 开始扫描", type="primary", use_container_width=True):
            if target:
                scan_options['timeout'] = timeout
                task = TaskManager.create_task(target, scan_options)
                st.session_state.current_task = task['id']
                st.success(f"✅ 任务创建成功！任务ID: `{task['id']}`")
                st.balloons()
                st.rerun()
            else:
                st.error("⚠️ 请输入扫描目标")

def show_task_list():
    st.markdown('<h2 style="color: #1E88E5;">📋 任务列表</h2>', unsafe_allow_html=True)
    
    if not st.session_state.tasks:
        st.info("📭 暂无任务，请先创建新任务")
        return
    
    for idx, task in enumerate(reversed(st.session_state.tasks)):
        status_color = {
            'pending': '⚪',
            'running': '🔵',
            'completed': '🟢',
            'failed': '🔴'
        }
        
        with st.expander(f"{status_color.get(task['status'], '⚪')} 任务 {task['id']} | {task['target']} | {task['status'].upper()}", expanded=False):
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.markdown(f"**🎯 目标**")
                st.code(task['target'])
            
            with col2:
                st.markdown(f"**📊 状态**")
                st.write(f"{status_color.get(task['status'], '⚪')} {task['status'].upper()}")
            
            with col3:
                st.markdown(f"**📈 进度**")
                st.progress(task['progress'] / 100)
                st.caption(f"{task['progress']}%")
            
            with col4:
                st.markdown(f"**🕐 创建时间**")
                st.caption(task['created_at'])
            
            with col5:
                st.markdown(f"**⚙️ 操作**")
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    if st.button("查看", key=f"view_{task['id']}", use_container_width=True):
                        st.session_state.current_task = task['id']
                        st.rerun()
                with col_btn2:
                    if st.button("删除", key=f"del_{task['id']}", use_container_width=True):
                        TaskManager.delete_task(task['id'])
                        st.rerun()
            
            if task['options']:
                st.markdown("**🔧 扫描选项:**")
                options_text = ", ".join([f"`{k}`" for k, v in task['options'].items() if v and k != 'timeout'])
                st.markdown(options_text)

def show_task_details():
    if not st.session_state.current_task:
        st.info("📋 请先选择一个任务查看详情")
        return
    
    task = TaskManager.get_task(st.session_state.current_task)
    if not task:
        st.error("❌ 任务不存在")
        return
    
    st.markdown(f'<h2 style="color: #1E88E5;">📊 任务详情: {task["target"]}</h2>', unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("任务ID", task['id'])
    with col2:
        st.metric("状态", task['status'].upper())
    with col3:
        st.metric("进度", f"{task['progress']}%")
    with col4:
        st.metric("创建时间", task['created_at'])
    
    if task['status'] == 'running':
        st.progress(task['progress'] / 100)
        st.info("⏳ 扫描进行中，请稍候...")
        return
    
    if task['status'] == 'completed' and st.session_state.current_task in st.session_state.scan_results:
        show_scan_results(st.session_state.scan_results[st.session_state.current_task])
    elif task['status'] == 'pending':
        st.info("📋 任务等待中，即将开始扫描...")

def show_scan_results(results):
    st.markdown("---")
    st.markdown('<h3 style="color: #4CAF50;">✅ 扫描结果</h3>', unsafe_allow_html=True)
    
    total_findings = sum(len(v) for v in results.values() if isinstance(v, list))
    st.success(f"共发现 {total_findings} 条有效信息")
    
    tabs = st.tabs(["🌐 子域名", "🔌 端口", "📁 目录", "🔍 指纹", "🌍 DNS信息"])
    
    with tabs[0]:
        if results.get('subdomains'):
            st.markdown(f"**发现 {len(results['subdomains'])} 个子域名**")
            for sub in results['subdomains']:
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.code(sub['domain'])
                with col2:
                    st.success(sub.get('ip', 'N/A'))
            st.download_button("📥 下载子域名CSV", 
                             data="\n".join([f"{s['domain']},{s.get('ip','')}" for s in results['subdomains']]),
                             file_name="subdomains.csv")
        else:
            st.info("未发现子域名")
    
    with tabs[1]:
        if results.get('ports'):
            st.markdown(f"**发现 {len(results['ports'])} 个开放端口**")
            for port in results['ports']:
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.code(f"{port['ip']}:{port['port']}")
                with col2:
                    st.write(f"服务: {port.get('service', 'Unknown')}")
                with col3:
                    st.write(f"协议: {port.get('protocol', 'TCP')}")
                with col4:
                    st.success(port['status'])
            st.download_button("📥 下载端口CSV",
                             data="\n".join([f"{p['ip']},{p['port']},{p.get('service','')}" for p in results['ports']]),
                             file_name="ports.csv")
        else:
            st.info("未发现开放端口")
    
    with tabs[2]:
        if results.get('directories'):
            st.markdown(f"**发现 {len(results['directories'])} 个目录/文件**")
            for dir_info in results['directories']:
                col1, col2, col3 = st.columns([3, 1, 1])
                with col1:
                    st.code(dir_info['url'])
                with col2:
                    st.write(f"状态: {dir_info['status_code']}")
                with col3:
                    st.write(f"大小: {dir_info.get('size', 0)} bytes")
            st.download_button("📥 下载目录CSV",
                             data="\n".join([f"{d['url']},{d['status_code']}" for d in results['directories']]),
                             file_name="directories.csv")
        else:
            st.info("未发现目录")
    
    with tabs[3]:
        if results.get('fingerprints'):
            st.markdown(f"**识别到 {len(results['fingerprints'])} 个技术组件**")
            for fp in results['fingerprints']:
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.code(fp['target'])
                with col2:
                    st.write(f"**{fp['technology']}**")
                with col3:
                    st.write(f"版本: {fp['version']}")
            st.download_button("📥 下载指纹CSV",
                             data="\n".join([f"{f['target']},{f['technology']},{f['version']}" for f in results['fingerprints']]),
                             file_name="fingerprints.csv")
        else:
            st.info("未识别到技术指纹")
    
    with tabs[4]:
        if results.get('dns'):
            st.markdown("**DNS 记录信息**")
            for record_type, records in results['dns'].items():
                if records:
                    st.markdown(f"**{record_type.replace('_', ' ').title()}:**")
                    for record in records:
                        st.code(record)
        else:
            st.info("未获取到DNS信息")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📄 生成完整报告", type="primary", use_container_width=True):
            report_gen = ReportGenerator()
            report_path = report_gen.generate_report(results, task['target'])
            st.success(f"✅ 报告已生成: `{report_path}`")
    
    with col2:
        if os.path.exists(f"reports/pentest_report_{task['target']}_"):
            files = [f for f in os.listdir("reports") if f.startswith(f"pentest_report_{task['target']}_")]
            if files:
                latest = sorted(files)[-1]
                with open(f"reports/{latest}", 'rb') as f:
                    st.download_button("📥 下载报告文件", f, file_name=latest, use_container_width=True)

def run_scan(task_id):
    task = TaskManager.get_task(task_id)
    if not task:
        return
    
    TaskManager.update_task(task_id, {'status': 'running', 'progress': 5})
    
    scanner = Scanner(task['target'], task['options'])
    results = scanner.run()
    
    st.session_state.scan_results[task_id] = results
    TaskManager.update_task(task_id, {'status': 'completed', 'progress': 100})

def main():
    st.sidebar.markdown("""
    <div style="text-align: center; padding: 1rem 0;">
        <h2 style="color: #1E88E5;">🛡️ 功能菜单</h2>
    </div>
    """, unsafe_allow_html=True)
    
    menu = {
        "仪表盘": "📊",
        "创建任务": "📝",
        "任务列表": "📋",
        "任务详情": "📊"
    }
    
    choice = st.sidebar.radio("选择功能", list(menu.keys()), format_func=lambda x: f"{menu[x]} {x}")
    
    if choice == "仪表盘":
        show_dashboard()
    elif choice == "创建任务":
        show_task_creation()
    elif choice == "任务列表":
        show_task_list()
    elif choice == "任务详情":
        show_task_details()
    
    for task in st.session_state.tasks:
        if task['status'] == 'pending':
            run_scan(task['id'])
            st.rerun()

if __name__ == "__main__":
    main()