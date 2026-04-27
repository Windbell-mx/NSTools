"""
数据持久化模块 - 负责任务和扫描结果的持久化存储
"""

import os
import json
from datetime import datetime

class DataStore:
    """数据存储类 - 使用JSON文件持久化存储"""
    
    def __init__(self):
        """初始化数据存储"""
        self.data_dir = "data"
        self.tasks_file = os.path.join(self.data_dir, "tasks.json")
        self.results_file = os.path.join(self.data_dir, "results.json")
        
        # 确保数据目录存在
        os.makedirs(self.data_dir, exist_ok=True)
        
        # 初始化文件（如果不存在）
        if not os.path.exists(self.tasks_file):
            self._write_json(self.tasks_file, [])
        if not os.path.exists(self.results_file):
            self._write_json(self.results_file, {})
    
    def _read_json(self, filepath):
        """读取JSON文件"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None
    
    def _write_json(self, filepath, data):
        """写入JSON文件"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except:
            return False
    
    # ============ 任务相关操作 ============
    
    def load_tasks(self):
        """加载所有任务"""
        data = self._read_json(self.tasks_file)
        return data if data else []
    
    def save_tasks(self, tasks):
        """保存所有任务"""
        return self._write_json(self.tasks_file, tasks)
    
    def add_task(self, task):
        """添加任务"""
        tasks = self.load_tasks()
        tasks.append(task)
        return self.save_tasks(tasks)
    
    def update_task(self, task_id, updates):
        """更新任务"""
        tasks = self.load_tasks()
        for i, task in enumerate(tasks):
            if task['id'] == task_id:
                tasks[i].update(updates)
                tasks[i]['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                break
        return self.save_tasks(tasks)
    
    def get_task(self, task_id):
        """获取任务"""
        tasks = self.load_tasks()
        for task in tasks:
            if task['id'] == task_id:
                return task
        return None
    
    def delete_task(self, task_id):
        """删除任务"""
        tasks = self.load_tasks()
        tasks = [t for t in tasks if t['id'] != task_id]
        self.save_tasks(tasks)
        
        # 同时删除对应的结果
        self.delete_results(task_id)
    
    # ============ 扫描结果相关操作 ============
    
    def load_results(self):
        """加载所有扫描结果"""
        data = self._read_json(self.results_file)
        return data if data else {}
    
    def save_results(self, results):
        """保存所有扫描结果"""
        return self._write_json(self.results_file, results)
    
    def save_result(self, task_id, result):
        """保存单个扫描结果"""
        results = self.load_results()
        results[task_id] = result
        return self.save_results(results)
    
    def get_result(self, task_id):
        """获取扫描结果"""
        results = self.load_results()
        return results.get(task_id)
    
    def delete_results(self, task_id):
        """删除扫描结果"""
        results = self.load_results()
        if task_id in results:
            del results[task_id]
            self.save_results(results)
    
    # ============ 清理操作 ============
    
    def clear_all(self):
        """清空所有数据"""
        self.save_tasks([])
        self.save_results({})