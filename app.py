"""
渗透测试信息收集平台 - 主应用程序
功能：自动化收集域名/子域名、IP、目录/接口、指纹、端口等信息
"""

import streamlit as st
import os
from datetime import datetime
from modules.scanner import Scanner      # 扫描器模块
from modules.report_generator import ReportGenerator  # 报告生成模块

# 配置页面设置
st.set_page_config(
    page_title="渗透测试信息收集平台",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"  # 默认收窄侧边栏
)

# 自定义CSS样式
st.markdown("""
<style>
    /* 收窄侧边栏宽度 */
    section[data-testid="stSidebar"] {
        width: 180px !important;
    }
    
    /* 侧边栏内容样式 */
    .sidebar-content {
        padding: 1rem;
    }
    
    /* 功能卡片样式 */
    .feature-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 3px solid #1E88E5;
    }
    
    /* 扫描选项区域 */
    .scan-options {
        background: #f0f4f8;
        padding: 1rem;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# 初始化会话状态变量
if 'tasks' not in st.session_state:
    st.session_state.tasks = []          # 存储所有任务

if 'current_task' not in st.session_state:
    st.session_state.current_task = None # 当前选中的任务ID

if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}   # 存储扫描结果

class TaskManager:
    """任务管理器类 - 负责任务的创建、更新、查询和删除"""
    
    @staticmethod
    def create_task(target: str, scan_options: dict) -> dict:
        """创建新任务"""
        import uuid
        task = {
            'id': str(uuid.uuid4())[:8],  # 生成8位短ID
            'target': target,              # 扫描目标
            'options': scan_options,       # 扫描选项
            'status': 'pending',           # 状态: pending/running/completed/failed
            'progress': 0,                 # 进度百分比
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        st.session_state.tasks.append(task)
        return task

    @staticmethod
    def update_task(task_id: str, updates: dict):
        """更新任务信息"""
        for task in st.session_state.tasks:
            if task['id'] == task_id:
                task.update(updates)
                task['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                break

    @staticmethod
    def get_task(task_id: str) -> dict:
        """根据ID获取任务"""
        for task in st.session_state.tasks:
            if task['id'] == task_id:
                return task
        return None

    @staticmethod
    def delete_task(task_id: str):
        """删除任务"""
        st.session_state.tasks = [t for t in st.session_state.tasks if t['id'] != task_id]
        if task_id in st.session_state.scan_results:
            del st.session_state.scan_results[task_id]

def show_dashboard():
    """显示仪表盘页面 - 统计信息和功能介绍"""
    st.title("🔍 渗透测试信息收集平台")
    
    # 统计指标
    col1, col2, col3, col4 = st.columns(4)
    
    total = len(st.session_state.tasks)
    completed = sum(1 for t in st.session_state.tasks if t['status'] == 'completed')
    running = sum(1 for t in st.session_state.tasks if t['status'] == 'running')
    pending = sum(1 for t in st.session_state.tasks if t['status'] == 'pending')
    
    col1.metric("总任务数", total)
    col2.metric("已完成", completed)
    col3.metric("运行中", running)
    col4.metric("等待中", pending)
    
    st.markdown("---")
    
    # 功能介绍 - 卡片式展开显示
    st.subheader("平台功能")
    features = [
        {"name": "子域名扫描", "desc": "自动发现目标域名的子域名", "icon": "🌐"},
        {"name": "端口扫描", "desc": "检测目标IP的开放端口", "icon": "🔌"},
        {"name": "目录扫描", "desc": "探测Web目录和敏感文件", "icon": "📁"},
        {"name": "指纹识别", "desc": "识别Web服务器和技术栈", "icon": "🔍"},
        {"name": "DNS收集", "desc": "获取DNS记录信息", "icon": "🌍"},
        {"name": "报告生成", "desc": "一键导出扫描报告", "icon": "📄"},
    ]
    
    cols = st.columns(3)
    for i, feature in enumerate(features):
        with cols[i % 3]:
            st.markdown(f"""
            <div class="feature-card">
                <h4>{feature['icon']} {feature['name']}</h4>
                <p style="color: #666; font-size: 0.9rem;">{feature['desc']}</p>
            </div>
            """, unsafe_allow_html=True)

def show_task_creation():
    """显示创建任务页面 - 输入目标和选择扫描选项"""
    st.title("创建扫描任务")
    
    # 目标输入
    target = st.text_input("目标域名/IP", placeholder="例如: example.com", help="输入要扫描的域名或IP地址")
    
    # 扫描选项 - 展开显示
    st.markdown("### 扫描模块选择")
    with st.expander("点击展开/收起扫描选项", expanded=True):
        st.markdown('<div class="scan-options">', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        scan_options = {}
        with col1:
            st.markdown("**🌐 信息收集**")
            scan_options['dns'] = st.checkbox("DNS信息收集", value=True)
            scan_options['subdomain'] = st.checkbox("子域名扫描", value=True)
            
            st.markdown("**🔎 服务扫描**")
            scan_options['port'] = st.checkbox("端口扫描", value=True)
        
        with col2:
            st.markdown("**📁 Web探测**")
            scan_options['directory'] = st.checkbox("目录扫描", value=True)
            scan_options['fingerprint'] = st.checkbox("指纹识别", value=True)
            
            st.markdown("**⚙️ 高级设置**")
            scan_options['timeout'] = st.number_input("请求超时(秒)", min_value=10, max_value=120, value=30)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # 显示已选模块数量
    selected_count = sum([
        scan_options.get('dns', False),
        scan_options.get('subdomain', False),
        scan_options.get('port', False),
        scan_options.get('directory', False),
        scan_options.get('fingerprint', False)
    ])
    
    col_info, col_button = st.columns([1, 3])
    with col_info:
        st.info(f"已选择 {selected_count} 个扫描模块")
    with col_button:
        if st.button("🚀 开始扫描", type="primary", use_container_width=True):
            if target:
                task = TaskManager.create_task(target, scan_options)
                st.session_state.current_task = task['id']
                st.success(f"✅ 任务创建成功！任务ID: {task['id']}")
                st.rerun()
            else:
                st.error("⚠️ 请输入扫描目标")

def show_task_list():
    """显示任务列表页面 - 展示所有任务及其状态"""
    st.title("任务列表")
    
    if not st.session_state.tasks:
        st.info("暂无任务，请先创建新任务")
        return
    
    # 遍历任务（倒序显示，最新的在前）
    for task in reversed(st.session_state.tasks):
        # 状态图标映射
        status_icon = {
            'pending': '⏳',
            'running': '🔄',
            'completed': '✅',
            'failed': '❌'
        }
        
        # 展开式卡片显示任务详情
        with st.expander(f"{status_icon.get(task['status'], '❓')} {task['id']} | {task['target']}", expanded=False):
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.write(f"**状态:** {task['status'].upper()}")
            with col2:
                st.write(f"**进度:** {task['progress']}%")
                st.progress(task['progress'] / 100)
            with col3:
                st.write(f"**创建时间:** {task['created_at']}")
            with col4:
                st.write(f"**扫描选项:**")
                if task['options']:
                    options = [k for k, v in task['options'].items() if v and k != 'timeout']
                    st.write(", ".join(options))
            
            # 操作按钮
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                st.button("查看详情", key=f"view_{task['id']}", on_click=lambda id=task['id']: setattr(st.session_state, 'current_task', id))
            with col_btn2:
                st.button("删除任务", key=f"del_{task['id']}", on_click=lambda id=task['id']: (TaskManager.delete_task(id), st.rerun()))

def show_task_details():
    """显示任务详情页面 - 展示任务状态和扫描结果"""
    st.title("任务详情")
    
    # 检查是否选择了任务
    if not st.session_state.current_task:
        st.info("请先从任务列表中选择一个任务")
        return
    
    task = TaskManager.get_task(st.session_state.current_task)
    if not task:
        st.error("任务不存在")
        return
    
    # 显示任务基本信息
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("目标", task['target'])
    col2.metric("任务ID", task['id'])
    col3.metric("状态", task['status'].upper())
    col4.metric("进度", f"{task['progress']}%")
    
    # 显示进度条（运行中）
    if task['status'] == 'running':
        st.progress(task['progress'] / 100)
        st.info("扫描进行中，请稍候...")
        return
    
    # 显示扫描结果（已完成）
    if task['status'] == 'completed' and st.session_state.current_task in st.session_state.scan_results:
        show_scan_results(st.session_state.scan_results[st.session_state.current_task], task['target'])

def show_scan_results(results, target):
    """显示扫描结果 - 子域名、端口、目录、指纹、DNS"""
    st.markdown("---")
    st.subheader("扫描结果")
    
    # 使用标签页展示不同类型的结果
    tabs = st.tabs(["子域名", "端口", "目录", "指纹", "DNS"])
    
    # 子域名结果
    with tabs[0]:
        if results.get('subdomains'):
            st.write(f"共发现 {len(results['subdomains'])} 个子域名")
            for sub in results['subdomains']:
                st.write(f"- **{sub['domain']}** | IP: {sub.get('ip', 'N/A')}")
        else:
            st.info("未发现子域名")
    
    # 端口结果
    with tabs[1]:
        if results.get('ports'):
            st.write(f"共发现 {len(results['ports'])} 个开放端口")
            for port in results['ports']:
                st.write(f"- **{port['ip']}:{port['port']}** | 服务: {port.get('service', 'Unknown')}")
        else:
            st.info("未发现开放端口")
    
    # 目录结果
    with tabs[2]:
        if results.get('directories'):
            st.write(f"共发现 {len(results['directories'])} 个目录/文件")
            for d in results['directories']:
                st.write(f"- **{d['url']}** | 状态码: {d['status_code']}")
        else:
            st.info("未发现目录")
    
    # 指纹结果
    with tabs[3]:
        if results.get('fingerprints'):
            st.write(f"共识别到 {len(results['fingerprints'])} 个技术组件")
            for fp in results['fingerprints']:
                st.write(f"- **{fp['target']}** | {fp['technology']}: {fp['version']}")
        else:
            st.info("未识别到技术指纹")
    
    # DNS结果
    with tabs[4]:
        if results.get('dns'):
            st.write("DNS记录信息:")
            for record_type, records in results['dns'].items():
                if records:
                    st.write(f"**{record_type.replace('_', ' ').title()}:**")
                    for record in records:
                        st.write(f"  - {record}")
        else:
            st.info("未获取到DNS信息")
    
    # 生成报告按钮
    if st.button("📄 生成完整报告", type="primary"):
        report_gen = ReportGenerator()
        report_path = report_gen.generate_report(results, target)
        st.success(f"报告已生成: {report_path}")
        
        # 下载报告
        with open(report_path, 'rb') as f:
            st.download_button("📥 下载报告文件", f, file_name=os.path.basename(report_path))

def run_scan(task_id):
    """执行扫描任务"""
    task = TaskManager.get_task(task_id)
    if not task:
        return
    
    # 更新状态为运行中
    TaskManager.update_task(task_id, {'status': 'running', 'progress': 5})
    
    # 创建扫描器并执行扫描
    scanner = Scanner(task['target'], task['options'])
    results = scanner.run()
    
    # 保存结果并更新状态
    st.session_state.scan_results[task_id] = results
    TaskManager.update_task(task_id, {'status': 'completed', 'progress': 100})

def main():
    """主函数 - 渲染侧边栏导航和页面内容"""
    with st.sidebar:
        st.markdown('<div class="sidebar-content">', unsafe_allow_html=True)
        st.title("导航")
        menu = ["仪表盘", "创建任务", "任务列表", "任务详情"]
        choice = st.radio("", menu, index=0)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # 根据选择显示不同页面
    if choice == "仪表盘":
        show_dashboard()
    elif choice == "创建任务":
        show_task_creation()
    elif choice == "任务列表":
        show_task_list()
    elif choice == "任务详情":
        show_task_details()
    
    # 检查并执行待处理的任务
    for task in st.session_state.tasks:
        if task['status'] == 'pending':
            run_scan(task['id'])
            st.rerun()

if __name__ == "__main__":
    main()