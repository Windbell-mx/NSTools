"""
渗透测试信息收集平台 - 主应用程序
功能：自动化收集域名/子域名、IP、目录/接口、指纹、端口等信息
支持：FOFA、Shodan、Hunter、ZoomEye等网络空间测绘平台
支持数据持久化存储
"""

import streamlit as st
import os
from datetime import datetime
from modules.scanner import Scanner                  # 扫描器模块
from modules.report_generator import ReportGenerator  # 报告生成模块
from modules.config_manager import ConfigManager      # 配置管理模块
from modules.mapping_api import MappingScanner        # 测绘平台API模块
from modules.data_store import DataStore              # 数据持久化模块

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

    /* 配置卡片样式 */
    .config-card {
        background: #fff;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# 初始化数据存储
data_store = DataStore()

# 初始化会话状态变量（从持久化存储加载）
if 'tasks' not in st.session_state:
    st.session_state.tasks = data_store.load_tasks()

if 'current_task' not in st.session_state:
    st.session_state.current_task = None

if 'scan_results' not in st.session_state:
    st.session_state.scan_results = data_store.load_results()

if 'config' not in st.session_state:
    st.session_state.config = {}

# 加载配置
config_manager = ConfigManager()
st.session_state.config = config_manager.load_config()

class TaskManager:
    """任务管理器类 - 负责任务的创建、更新、查询和删除"""

    @staticmethod
    def create_task(target: str, scan_options: dict) -> dict:
        """创建新任务"""
        import uuid
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
        data_store.save_tasks(st.session_state.tasks)
        return task

    @staticmethod
    def update_task(task_id: str, updates: dict):
        """更新任务信息"""
        for task in st.session_state.tasks:
            if task['id'] == task_id:
                task.update(updates)
                task['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                break
        data_store.save_tasks(st.session_state.tasks)

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
        data_store.save_tasks(st.session_state.tasks)
        if task_id in st.session_state.scan_results:
            del st.session_state.scan_results[task_id]
            data_store.save_results(st.session_state.scan_results)

def show_dashboard():
    """显示仪表盘页面"""
    st.title("🔍 渗透测试信息收集平台")

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

    features = [
        {"name": "子域名扫描", "desc": "自动发现目标域名的子域名", "icon": "🌐"},
        {"name": "端口扫描", "desc": "检测目标IP的开放端口", "icon": "🔌"},
        {"name": "目录扫描", "desc": "探测Web目录和敏感文件", "icon": "📁"},
        {"name": "指纹识别", "desc": "识别Web服务器和技术栈", "icon": "🔍"},
        {"name": "DNS收集", "desc": "获取DNS记录信息", "icon": "🌍"},
        {"name": "测绘搜索", "desc": "集成FOFA、Shodan等平台", "icon": "🔭"},
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

    st.markdown("---")
    st.subheader("🔭 网络空间测绘搜索")

    enabled_platforms = [p for p in ['fofa', 'shodan', 'hunter', 'zoomeye']
                         if st.session_state.config.get(p, {}).get('enabled')]

    if enabled_platforms:
        query = st.text_input("搜索关键词", placeholder="例如: domain=\"example.com\"")
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("搜索", use_container_width=True):
                if query:
                    mapping_scanner = MappingScanner(st.session_state.config)
                    results = mapping_scanner.search(query)

                    st.session_state.mapping_results = results
                    st.success(f"搜索完成，已查询 {len(results)} 个平台")
                else:
                    st.error("请输入搜索关键词")

        if 'mapping_results' in st.session_state:
            results = st.session_state.mapping_results
            for platform, data in results.items():
                st.markdown(f"### {config_manager.get_platform_info(platform).get('name', platform)}")
                if 'error' in data:
                    st.error(f"错误: {data['error']}")
                else:
                    st.json(data)
    else:
        st.info("请先在「系统设置」中配置并启用测绘平台")

def show_task_creation():
    """显示创建任务页面"""
    st.title("创建扫描任务")

    target = st.text_input("目标域名/IP", placeholder="例如: example.com", help="输入要扫描的域名或IP地址")

    st.markdown("### 扫描模块选择")
    with st.expander("点击展开/收起扫描选项", expanded=True):
        st.markdown('<div class="scan-options">', unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        scan_options = {}
        with col1:
            st.markdown("**🌐 信息收集**")
            scan_options['dns'] = st.checkbox("DNS信息收集", value=True)
            scan_options['subdomain'] = st.checkbox("子域名扫描", value=True)
            scan_options['whois'] = st.checkbox("WHOIS信息", value=True)

            st.markdown("**🔎 服务扫描**")
            scan_options['port'] = st.checkbox("端口扫描", value=True)
            scan_options['fingerprint'] = st.checkbox("指纹识别", value=True)

        with col2:
            st.markdown("**📁 Web探测**")
            scan_options['directory'] = st.checkbox("目录扫描", value=True)
            scan_options['sensitive'] = st.checkbox("敏感文件探测", value=True)

            st.markdown("**🛡️ 安全检测**")
            scan_options['ssl'] = st.checkbox("SSL证书检测", value=True)
            scan_options['waf'] = st.checkbox("WAF识别", value=True)
            scan_options['cdn'] = st.checkbox("CDN识别", value=True)
            scan_options['cloud'] = st.checkbox("云服务识别", value=True)
            scan_options['icp'] = st.checkbox("ICP备案查询", value=True)

            st.markdown("**⚙️ 高级设置**")
            scan_options['timeout'] = st.number_input("请求超时(秒)", min_value=10, max_value=120, value=30)

        st.markdown('</div>', unsafe_allow_html=True)

    selected_count = sum([
        scan_options.get('dns', False),
        scan_options.get('subdomain', False),
        scan_options.get('whois', False),
        scan_options.get('port', False),
        scan_options.get('fingerprint', False),
        scan_options.get('directory', False),
        scan_options.get('sensitive', False),
        scan_options.get('ssl', False),
        scan_options.get('waf', False),
        scan_options.get('cdn', False),
        scan_options.get('cloud', False),
        scan_options.get('icp', False)
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
    """显示任务列表页面"""
    st.title("任务列表")

    if not st.session_state.tasks:
        st.info("暂无任务，请先创建新任务")
        return

    status_map = {
        'pending': '等待中',
        'running': '运行中',
        'completed': '已完成',
        'failed': '失败'
    }

    option_map = {
        'dns': 'DNS收集',
        'subdomain': '子域名扫描',
        'whois': 'WHOIS信息',
        'port': '端口扫描',
        'fingerprint': '指纹识别',
        'directory': '目录扫描',
        'sensitive': '敏感文件探测',
        'ssl': 'SSL证书检测',
        'waf': 'WAF识别',
        'cdn': 'CDN识别',
        'cloud': '云服务识别',
        'icp': 'ICP备案查询'
    }

    for task in reversed(st.session_state.tasks):
        status_icon = {
            'pending': '⏳',
            'running': '🔄',
            'completed': '✅',
            'failed': '❌'
        }

        with st.expander(f"{status_icon.get(task['status'], '❓')} {task['id']} | {task['target']} | {status_map.get(task['status'], task['status'])}", expanded=False):
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.write(f"**状态:** {status_map.get(task['status'], task['status'])}")
            with col2:
                st.write(f"**进度:** {task['progress']}%")
                st.progress(task['progress'] / 100)
            with col3:
                st.write(f"**创建时间:** {task['created_at']}")
            with col4:
                st.write(f"**扫描选项:**")
                if task['options']:
                    options = [option_map.get(k, k) for k, v in task['options'].items() if v and k != 'timeout']
                    st.write(", ".join(options))

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                st.button("查看详情", key=f"view_{task['id']}", on_click=lambda id=task['id']: setattr(st.session_state, 'current_task', id))
            with col_btn2:
                st.button("删除任务", key=f"del_{task['id']}", on_click=lambda id=task['id']: (TaskManager.delete_task(id), st.rerun()))

def show_task_details():
    """显示任务详情页面"""
    st.title("任务详情")

    status_map = {
        'pending': '等待中',
        'running': '运行中',
        'completed': '已完成',
        'failed': '失败'
    }

    if not st.session_state.current_task:
        st.info("请先从任务列表中选择一个任务")
        return

    task = TaskManager.get_task(st.session_state.current_task)
    if not task:
        st.error("任务不存在")
        return

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("目标", task['target'])
    col2.metric("任务ID", task['id'])
    col3.metric("状态", status_map.get(task['status'], task['status']))
    col4.metric("进度", f"{task['progress']}%")

    if task['status'] == 'running':
        st.markdown("---")
        st.subheader("🔄 扫描进度")

        st.markdown(f"""
        <div style="height: 24px; background-color: #e0e0e0; border-radius: 12px; overflow: hidden;">
            <div style="height: 100%; width: {task['progress']}%; background: linear-gradient(90deg, #1E88E5, #42A5F5); transition: width 0.5s ease;"></div>
        </div>
        """, unsafe_allow_html=True)

        progress_info = st.session_state.get('task_progress', {'stage': '初始化', 'details': '正在准备...'})

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**当前阶段:** {progress_info['stage']}")
        with col2:
            st.markdown(f"**进度:** {task['progress']}%")

        st.markdown(f"**详细信息:** {progress_info['details']}")

        st.markdown("---")
        st.subheader("📋 扫描阶段")

        stages = [
            ('dns', 'DNS收集', 15),
            ('whois', 'WHOIS信息', 20),
            ('subdomain', '子域名扫描', 35),
            ('port', '端口扫描', 50),
            ('directory', '目录扫描', 65),
            ('sensitive', '敏感文件', 75),
            ('fingerprint', '指纹识别', 85),
            ('ssl', 'SSL检测', 88),
            ('waf', 'WAF识别', 90),
            ('cdn', 'CDN识别', 92),
            ('cloud', '云服务', 94),
            ('icp', 'ICP备案', 96),
        ]

        for option, stage_name, progress in stages:
            if task['options'].get(option, False):
                status = "✅" if task['progress'] >= progress else "🔄" if task['progress'] > 0 and task['progress'] < progress else "⏳"
                st.write(f"{status} {stage_name}")

        st.rerun()
        return

    if task['status'] == 'completed' and st.session_state.current_task in st.session_state.scan_results:
        show_scan_results(st.session_state.scan_results[st.session_state.current_task], task['target'])

def display_table(data, columns):
    """通用表格显示函数"""
    if not data:
        return

    html = "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
    html += "<thead><tr>"
    for col in columns:
        html += f"<th style='border:1px solid #ddd;padding:8px;text-align:left;background-color:#f5f5f5;'>{col}</th>"
    html += "</tr></thead><tbody>"

    for row in data:
        html += "<tr>"
        for col in columns:
            value = row.get(col, '')
            if col == '状态':
                value = '✅ 有效' if value == '有效' else '⚠️ 待验证' if value == '待验证' else value
            elif col == '状态码':
                if value == 200:
                    value = f'🟢 {value}'
                elif value in [301, 302]:
                    value = f'🟡 {value}'
                else:
                    value = f'🔵 {value}'
            html += f"<td style='border:1px solid #ddd;padding:8px;'>{value}</td>"
        html += "</tr>"

    html += "</tbody></table>"
    st.markdown(html, unsafe_allow_html=True)

def show_scan_results(results, target):
    """显示扫描结果"""
    st.markdown("---")
    st.subheader("扫描结果")

    if results.get('summary'):
        summary = results['summary']
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("子域名总数", summary.get('total_subdomains', 0))
        col2.metric("有效子域名", summary.get('valid_subdomains', 0))
        col3.metric("开放端口", summary.get('open_ports', 0))
        col4.metric("发现目录", summary.get('total_directories', 0))

    tabs = st.tabs(["子域名", "端口", "目录", "敏感文件", "指纹", "DNS", "WHOIS", "SSL证书", "WAF/CDN/云服务", "ICP备案"])

    with tabs[0]:
        if results.get('subdomains'):
            display_table(results['subdomains'], ['域名', 'IP地址', '状态', '来源'])
        else:
            st.info("未发现子域名")

    with tabs[1]:
        if results.get('ports'):
            display_table(results['ports'], ['IP地址', '端口', '服务', '状态', '协议'])
        else:
            st.info("未发现开放端口")

    with tabs[2]:
        if results.get('directories'):
            display_table(results['directories'], ['URL', '状态码', '内容类型', '大小'])
        else:
            st.info("未发现目录")

    with tabs[3]:
        if results.get('sensitive_files'):
            display_table(results['sensitive_files'], ['URL', '状态码', '文件类型'])
        else:
            st.info("未发现敏感文件")

    with tabs[4]:
        if results.get('fingerprints'):
            display_table(results['fingerprints'], ['目标', '技术', '版本'])
        else:
            st.info("未识别到技术指纹")

    with tabs[5]:
        if results.get('dns'):
            for record_type, records in results['dns'].items():
                if records:
                    st.write(f"**{record_type}:**")
                    st.write(", ".join(records))
                    st.write("")
        else:
            st.info("未获取到DNS信息")

    with tabs[6]:
        if results.get('whois'):
            for key, value in results['whois'].items():
                if value:
                    st.write(f"**{key}:** {value}")
        else:
            st.info("未获取到WHOIS信息")

    with tabs[7]:
        if results.get('ssl'):
            for key, value in results['ssl'].items():
                if value:
                    st.write(f"**{key}:** {value}")
        else:
            st.info("未获取到SSL证书信息")

    with tabs[8]:
        col1, col2, col3 = st.columns(3)

        with col1:
            st.write("**🛡️ WAF识别:**")
            if results.get('waf'):
                for waf in results['waf']:
                    st.write(f"- {waf.get('名称', '')}")
            else:
                st.info("未识别到WAF")

        with col2:
            st.write("**☁️ CDN识别:**")
            if results.get('cdn'):
                for cdn in results['cdn']:
                    st.write(f"- {cdn.get('名称', '')}")
            else:
                st.info("未识别到CDN")

        with col3:
            st.write("**🏢 云服务:**")
            if results.get('cloud'):
                for cloud in results['cloud']:
                    st.write(f"- {cloud.get('名称', '')}")
            else:
                st.info("未识别到云服务")

    with tabs[9]:
        if results.get('icp'):
            for key, value in results['icp'].items():
                if value:
                    st.write(f"**{key}:** {value}")
        else:
            st.info("未获取到ICP备案信息")

    if st.button("📄 生成完整报告", type="primary"):
        report_gen = ReportGenerator()
        report_path = report_gen.generate_report(results, target)
        st.success(f"报告已生成: {report_path}")

        with open(report_path, 'rb') as f:
            st.download_button("📥 下载报告文件", f, file_name=os.path.basename(report_path))

def show_settings():
    """显示系统设置页面"""
    st.title("系统设置")

    config = st.session_state.config
    platforms = config_manager.get_platforms()

    for platform in platforms:
        info = config_manager.get_platform_info(platform)
        st.markdown(f'<div class="config-card">', unsafe_allow_html=True)

        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader(f"{info.get('name', platform)}")
            st.write(info.get('description', ''))
            st.write(f"官网: [{info.get('url', '')}]({info.get('url', '')})")
        with col2:
            enabled = st.checkbox("启用", value=config.get(platform, {}).get('enabled'), key=f"enable_{platform}")

        if enabled:
            st.markdown("**API配置:**")
            fields = info.get('required_fields', [])

            for field in fields:
                if field == 'email':
                    config[platform]['email'] = st.text_input("邮箱", value=config.get(platform, {}).get('email', ''), key=f"{platform}_email")
                elif field == 'key':
                    config[platform]['key'] = st.text_input("API Key", value=config.get(platform, {}).get('key', ''), type="password", key=f"{platform}_key")
                elif field == 'api_key':
                    config[platform]['api_key'] = st.text_input("API Key", value=config.get(platform, {}).get('api_key', ''), type="password", key=f"{platform}_api_key")
                elif field == 'username':
                    config[platform]['username'] = st.text_input("用户名", value=config.get(platform, {}).get('username', ''), key=f"{platform}_username")
                elif field == 'password':
                    config[platform]['password'] = st.text_input("密码", value=config.get(platform, {}).get('password', ''), type="password", key=f"{platform}_password")

            config[platform]['enabled'] = True
        else:
            config[platform]['enabled'] = False

        st.markdown('</div>', unsafe_allow_html=True)

    if st.button("💾 保存配置", type="primary"):
        config_manager.save_config(config)
        st.session_state.config = config
        st.success("配置已保存！")

def run_scan(task_id):
    """执行扫描任务"""
    task = TaskManager.get_task(task_id)
    if not task:
        return

    TaskManager.update_task(task_id, {'status': 'running', 'progress': 5})

    st.session_state.task_progress = {
        'stage': '初始化',
        'details': '正在准备扫描任务...'
    }

    TaskManager.update_task(task_id, {'progress': 10})
    st.session_state.task_progress = {'stage': '初始化', 'details': '扫描器已就绪'}

    scanner = Scanner(task['target'], task['options'])

    options = task['options']
    current_progress = 10

    if options.get('dns', False):
        st.session_state.task_progress = {'stage': 'DNS信息收集', 'details': '正在查询DNS记录...'}
        scanner.raw_results['dns'] = scanner.collect_dns_info()
        current_progress += 5
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('whois', False):
        st.session_state.task_progress = {'stage': 'WHOIS信息收集', 'details': '正在查询WHOIS记录...'}
        scanner.raw_results['whois'] = scanner.collect_whois_info()
        current_progress += 5
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('subdomain', False):
        st.session_state.task_progress = {'stage': '子域名扫描', 'details': '正在发现子域名...'}
        scanner.raw_results['subdomains'] = scanner.discover_subdomains()
        current_progress += 15
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('port', False):
        st.session_state.task_progress = {'stage': '端口扫描', 'details': '正在扫描开放端口...'}
        scanner.raw_results['ports'] = scanner.scan_ports()
        current_progress += 15
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('directory', False):
        st.session_state.task_progress = {'stage': '目录扫描', 'details': '正在探测Web目录...'}
        scanner.raw_results['directories'] = scanner.scan_directories()
        current_progress += 15
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('sensitive', False):
        st.session_state.task_progress = {'stage': '敏感文件探测', 'details': '正在检测敏感文件...'}
        scanner.raw_results['sensitive_files'] = scanner.scan_sensitive_files()
        current_progress += 10
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('fingerprint', False):
        st.session_state.task_progress = {'stage': '指纹识别', 'details': '正在识别技术栈...'}
        scanner.raw_results['fingerprints'] = scanner.identify_fingerprints()
        current_progress += 10
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('ssl', False):
        st.session_state.task_progress = {'stage': 'SSL证书检测', 'details': '正在获取SSL证书...'}
        scanner.raw_results['ssl'] = scanner.collect_ssl_info()
        current_progress += 3
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('waf', False):
        st.session_state.task_progress = {'stage': 'WAF识别', 'details': '正在检测WAF...'}
        scanner.raw_results['waf'] = scanner.detect_waf()
        current_progress += 2
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('cdn', False):
        st.session_state.task_progress = {'stage': 'CDN识别', 'details': '正在识别CDN...'}
        scanner.raw_results['cdn'] = scanner.detect_cdn()
        current_progress += 2
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('cloud', False):
        st.session_state.task_progress = {'stage': '云服务识别', 'details': '正在识别云服务商...'}
        scanner.raw_results['cloud'] = scanner.detect_cloud()
        current_progress += 2
        TaskManager.update_task(task_id, {'progress': current_progress})

    if options.get('icp', False):
        st.session_state.task_progress = {'stage': 'ICP备案查询', 'details': '正在查询备案信息...'}
        scanner.raw_results['icp'] = scanner.query_icp_info()
        current_progress += 2
        TaskManager.update_task(task_id, {'progress': current_progress})

    st.session_state.task_progress = {'stage': '数据处理', 'details': '正在验证、清洗、去重...'}
    current_progress = 98
    TaskManager.update_task(task_id, {'progress': current_progress})

    scanner.process_data()

    st.session_state.scan_results[task_id] = scanner.processed_results
    data_store.save_results(st.session_state.scan_results)

    st.session_state.task_progress = {'stage': '完成', 'details': '扫描完成！'}
    TaskManager.update_task(task_id, {'status': 'completed', 'progress': 100})

def main():
    """主函数"""
    with st.sidebar:
        st.markdown('<div class="sidebar-content">', unsafe_allow_html=True)
        st.title("导航")
        menu = ["仪表盘", "创建任务", "任务列表", "任务详情", "系统设置"]
        choice = st.radio("导航菜单", menu, index=0, label_visibility="collapsed")
        st.markdown('</div>', unsafe_allow_html=True)

    if choice == "仪表盘":
        show_dashboard()
    elif choice == "创建任务":
        show_task_creation()
    elif choice == "任务列表":
        show_task_list()
    elif choice == "任务详情":
        show_task_details()
    elif choice == "系统设置":
        show_settings()

    for task in st.session_state.tasks:
        if task['status'] == 'pending':
            run_scan(task['id'])
            st.rerun()

if __name__ == "__main__":
    main()