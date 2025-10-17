# CapCut API 服务端 - Render 部署优化版
# 适配 Render 平台的特性和限制

from flask import Flask, request, jsonify
import hashlib
import secrets
import json
import os
from datetime import datetime
import threading
import random
import time
import itertools

# 导入现有的 CapCutAPI 类
from jimengfa import CapCutAPI, AccountDatabase

app = Flask(__name__)

# ==============================================================================
# Render 平台配置
# ==============================================================================

# 从环境变量读取配置
PORT = int(os.environ.get('PORT', 10000))
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'your_admin_password_here')
API_PASSWORD = os.environ.get('API_PASSWORD')  # 全局单口令（兼容 gcli2api 风格）

# 数据文件路径（Render 持久化磁盘）
DATA_DIR = os.environ.get('DATA_DIR', '.')
API_KEYS_FILE = os.path.join(DATA_DIR, 'api_keys.json')
ACCOUNTS_FILE = os.path.join(DATA_DIR, 'accounts_database.json')

print(f"[INFO] Render 部署模式")
print(f"[INFO] 端口: {PORT}")
print(f"[INFO] 数据目录: {DATA_DIR}")
print(f"[INFO] 管理员密码已设置: {'是' if ADMIN_PASSWORD != 'your_admin_password_here' else '否'}")
print(f"[INFO] API_PASSWORD 已设置: {'是' if API_PASSWORD else '否'}")

# ==============================================================================
# API Key 管理 - Render 优化版
# ==============================================================================
class APIKeyManagerRender:
    """API Key 管理器 - Render 平台优化版"""
    
    def __init__(self, db_file=API_KEYS_FILE):
        self.db_file = db_file
        self.api_keys = {}
        self.lock = threading.RLock()
        self.dirty = False
        self.load_keys()
        self.start_auto_save()
    
    def load_keys(self):
        """从文件加载 API Keys"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.api_keys = data.get('api_keys', {})
                    print(f"[INFO] 加载了 {len(self.api_keys)} 个 API Keys")
            else:
                print(f"[INFO] API Keys 文件不存在，将创建新文件")
        except Exception as e:
            print(f"[ERROR] 加载 API Keys 失败: {e}")
            self.api_keys = {}
    
    def save_keys(self):
        """保存 API Keys 到文件"""
        try:
            with self.lock:
                # 确保目录存在
                os.makedirs(os.path.dirname(self.db_file) or '.', exist_ok=True)
                
                data = {
                    'api_keys': self.api_keys,
                    'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # 原子写入
                temp_file = f"{self.db_file}.tmp"
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                # Windows 兼容的原子操作
                if os.path.exists(self.db_file):
                    os.remove(self.db_file)
                os.rename(temp_file, self.db_file)
                
                self.dirty = False
                return True
        except Exception as e:
            print(f"[ERROR] 保存 API Keys 失败: {e}")
            return False
    
    def start_auto_save(self):
        """启动自动保存线程（每30秒）"""
        def auto_save():
            while True:
                time.sleep(30)
                if self.dirty:
                    print("[INFO] 自动保存 API Keys...")
                    self.save_keys()
        
        thread = threading.Thread(target=auto_save, daemon=True, name="AutoSave-APIKeys")
        thread.start()
        print("[INFO] API Keys 自动保存线程已启动")
    
    def generate_key(self, user_id, quota=1000, description=""):
        """生成新的 API Key"""
        api_key = f"sk-{secrets.token_urlsafe(32)}"
        with self.lock:
            self.api_keys[api_key] = {
                'user_id': user_id,
                'quota': quota,
                'used': 0,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': description,
                'status': 'active'
            }
            self.dirty = True
        self.save_keys()
        return api_key
    
    def verify_key(self, api_key):
        """验证 API Key"""
        with self.lock:
            if api_key not in self.api_keys:
                return False, "Invalid API Key"
            
            key_info = self.api_keys[api_key].copy()
            
            if key_info['status'] != 'active':
                return False, "API Key is disabled"
            
            if key_info['quota'] <= 0:
                return False, "Quota exceeded"
            
            return True, key_info
    
    def consume_quota(self, api_key, amount=1):
        """消耗配额"""
        with self.lock:
            if api_key in self.api_keys:
                self.api_keys[api_key]['quota'] -= amount
                self.api_keys[api_key]['used'] += amount
                self.dirty = True
                return True
        return False

# ==============================================================================
# 账号池管理 - Render 优化版
# ==============================================================================
class AccountPoolRender:
    """账号池管理器 - Render 平台优化版"""
    
    def __init__(self, account_db):
        self.account_db = account_db
        self.account_cycle = None
        self.account_list = []
        self.failed_accounts = set()
        self.lock = threading.Lock()
        self.refresh_accounts()
        self.start_auto_refresh()
    
    def refresh_accounts(self):
        """刷新账号列表"""
        with self.lock:
            accounts = [acc for acc in self.account_db.get_all_accounts() 
                       if acc['status'] == 'active' and acc['id'] not in self.failed_accounts]
            
            if not accounts:
                print("[WARNING] 没有可用账号！")
                self.account_list = []
                self.account_cycle = None
                return
            
            self.account_list = accounts
            self.account_cycle = itertools.cycle(accounts)
            print(f"[INFO] 刷新账号池: {len(accounts)} 个可用账号")
    
    def start_auto_refresh(self):
        """启动自动刷新线程（每5分钟）"""
        def auto_refresh():
            while True:
                time.sleep(300)
                print("[INFO] 自动刷新账号池...")
                self.refresh_accounts()
        
        thread = threading.Thread(target=auto_refresh, daemon=True, name="AutoRefresh-AccountPool")
        thread.start()
        print("[INFO] 账号池自动刷新线程已启动")
    
    def get_available_account(self):
        """获取可用账号（无锁）"""
        if not self.account_cycle:
            return None, "No available accounts"
        
        try:
            account = next(self.account_cycle)
            return account, None
        except (StopIteration, AttributeError):
            return None, "No available accounts"
    
    def mark_account_failed(self, account_id):
        """标记账号失效"""
        with self.lock:
            self.failed_accounts.add(account_id)
            print(f"[WARNING] 账号 #{account_id} 已标记为失效")
            self.refresh_accounts()

# ==============================================================================
# 全局实例
# ==============================================================================

# 使用 Render 适配的数据库路径
class AccountDatabaseRender(AccountDatabase):
    def __init__(self, db_file=ACCOUNTS_FILE):
        self.db_file = db_file
        self.accounts = []
        self.load_database()

api_key_manager = APIKeyManagerRender()
account_db = AccountDatabaseRender()
account_pool = AccountPoolRender(account_db)

# ==============================================================================
# API 端点
# ==============================================================================

def require_api_key(f):
    """API Key 验证装饰器（兼容 gcli2api 风格）
    支持以下认证方式：
    - Authorization: Bearer <token>
    - x-goog-api-key: <token>
    - URL 参数: ?key=<token>
    - 若 token 等于环境变量 API_PASSWORD，则视为全局单口令通过
    - 否则按本地 API Key 管理器验证
    """
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '').strip()
        header_token = ''
        if auth_header:
            if auth_header.lower().startswith('bearer '):
                header_token = auth_header[7:].strip()
            else:
                header_token = auth_header

        x_api_key = request.headers.get('x-goog-api-key') or request.headers.get('X-Goog-Api-Key')
        url_key = request.args.get('key')

        token = header_token or x_api_key or url_key or ''

        if not token:
            return jsonify({
                'error': 'Missing API Key',
                'message': 'Provide token via Authorization Bearer / x-goog-api-key / ?key'
            }), 401

        # 单口令模式
        if API_PASSWORD and token == API_PASSWORD:
            key_info = {
                'user_id': 'api_password',
                'quota': 999_999_999,
                'used': 0,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': 'global password',
                'status': 'active',
                'is_password': True
            }
            return f(token, key_info, *args, **kwargs)

        # 本地 API Key 管理验证
        is_valid, result = api_key_manager.verify_key(token)
        if not is_valid:
            return jsonify({
                'error': 'Invalid API Key',
                'message': result
            }), 401

        result = result or {}
        result['is_password'] = False
        return f(token, result, *args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/', methods=['GET'])
def index():
    """首页"""
    return jsonify({
        'service': 'CapCut API Server',
        'version': 'render-optimized',
        'platform': 'Render.com',
        'status': 'running',
        'endpoints': {
            'health': '/health',
            'openai_images': '/v1/images/generations (OpenAI 兼容)',
            'models': '/v1/models (OpenAI 兼容模型列表)',
            'text_to_image': '/v1/text-to-image (自定义格式)',
            'query_task': '/v1/query-task/<submit_id>',
            'credit': '/v1/credit',
            'admin': '/admin/*'
        },
        'docs': 'https://github.com/your-repo/README.md'
    })

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查（Render 会定期访问此端点）"""
    stats = account_db.get_statistics()
    return jsonify({
        'status': 'ok',
        'version': 'render-optimized',
        'platform': 'render',
        'accounts': {
            'total': stats['total'],
            'active': stats['active'],
            'failed': stats['failed'],
            'in_pool': len(account_pool.account_list)
        },
        'api_keys': {
            'total': len(api_key_manager.api_keys),
            'active': len([k for k in api_key_manager.api_keys.values() if k['status'] == 'active'])
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/v1/images/generations', methods=['POST'])
@require_api_key
def openai_images_generations(api_key, key_info):
    """OpenAI 兼容的图片生成接口"""
    try:
        data = request.get_json()
        
        # OpenAI 格式: {"prompt": "...", "n": 1, "size": "1024x1024", "model": "..."}
        if not data or 'prompt' not in data:
            return jsonify({'error': {'message': 'Missing required field: prompt', 'type': 'invalid_request_error'}}), 400
        
        prompt = data['prompt']
        n = data.get('n', 1)  # 生成数量，默认1张
        size = data.get('size', '1024x1024')  # 图片尺寸（CapCut暂不支持，忽略）
        model = data.get('model', 'high_aes_general_v30l:general_v3.0_18b')
        negative_prompt = data.get('negative_prompt', '')
        
        # 获取账号
        account, error = account_pool.get_available_account()
        if error:
            return jsonify({'error': {'message': error, 'type': 'service_unavailable'}}), 503
        
        # 创建任务
        api = CapCutAPI(account['session_id'], account['did'])
        result = api.create_text_to_image_task(prompt, negative_prompt, model)
        
        if result.get('error'):
            if 'authentication' in str(result.get('error')).lower():
                account_pool.mark_account_failed(account['id'])
            return jsonify({'error': {'message': 'CapCut API Error', 'type': 'api_error', 'details': result}}), 500
        
        submit_id = result.get("data", {}).get("aigc_data", {}).get("submit_id")
        if not submit_id:
            return jsonify({'error': {'message': 'Failed to get submit_id', 'type': 'api_error'}}), 500
        
        # 消耗配额
        api_key_manager.consume_quota(api_key, 1)
        
        # OpenAI 格式响应
        return jsonify({
            'created': int(time.time()),
            'data': [{
                'submit_id': submit_id,
                'account_id': account['id'],
                'status': 'pending',
                'url': None  # 任务完成后通过 query 获取
            }],
            'quota_remaining': key_info['quota'] - 1,
            'usage': {
                'total_tokens': 1  # 按图片数量计费
            }
        })
        
    except Exception as e:
        print(f"[ERROR] openai_images_generations: {e}")
        return jsonify({'error': {'message': str(e), 'type': 'internal_error'}}), 500

@app.route('/v1/text-to-image', methods=['POST'])
@require_api_key
def text_to_image(api_key, key_info):
    """文生图接口（自定义格式，保持向后兼容）"""
    try:
        data = request.get_json()
        
        if not data or 'prompt' not in data:
            return jsonify({'error': 'Missing required field: prompt'}), 400
        
        prompt = data['prompt']
        negative_prompt = data.get('negative_prompt', '')
        model_key = data.get('model', 'high_aes_general_v30l:general_v3.0_18b')
        
        account, error = account_pool.get_available_account()
        if error:
            return jsonify({'error': 'Service Unavailable', 'message': error}), 503
        
        api = CapCutAPI(account['session_id'], account['did'])
        result = api.create_text_to_image_task(prompt, negative_prompt, model_key)
        
        if result.get('error'):
            if 'authentication' in str(result.get('error')).lower():
                account_pool.mark_account_failed(account['id'])
            return jsonify({'error': 'CapCut API Error', 'details': result}), 500
        
        submit_id = result.get("data", {}).get("aigc_data", {}).get("submit_id")
        if not submit_id:
            return jsonify({'error': 'Failed to get submit_id', 'details': result}), 500
        
        api_key_manager.consume_quota(api_key, 1)
        
        return jsonify({
            'success': True,
            'submit_id': submit_id,
            'account_id': account['id'],
            'message': 'Task submitted successfully',
            'quota_remaining': key_info['quota'] - 1
        })
        
    except Exception as e:
        print(f"[ERROR] text_to_image: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/v1/query-task/<submit_id>', methods=['GET'])
@require_api_key
def query_task(api_key, key_info, submit_id):
    """查询任务状态"""
    try:
        account_id = request.args.get('account_id', type=int)
        
        if account_id:
            accounts = [acc for acc in account_db.get_all_accounts() if acc['id'] == account_id]
            if not accounts:
                return jsonify({'error': 'Account not found'}), 404
            account = accounts[0]
        else:
            account, error = account_pool.get_available_account()
            if error:
                return jsonify({'error': error}), 503
        
        api = CapCutAPI(account['session_id'], account['did'])
        result = api.query_task_status(submit_id)
        
        if result.get('error'):
            return jsonify({'error': 'CapCut API Error', 'details': result}), 500
        
        task_data = result.get("data", {}).get(submit_id, {})
        status = task_data.get("status")
        item_list = task_data.get("item_list", [])
        
        response = {
            'success': True,
            'submit_id': submit_id,
            'status': status,
            'status_name': {20: 'processing', 10: 'completed', 30: 'failed'}.get(status, 'unknown'),
            'items': []
        }
        
        if status == 10 and item_list:
            for item in item_list:
                try:
                    image_url = item['image']['large_images'][0]['image_url']
                except (KeyError, IndexError, TypeError):
                    image_url = item.get('common_attr', {}).get('cover_url')
                
                if image_url:
                    response['items'].append({'type': 'image', 'url': image_url})
        
        return jsonify(response)
        
    except Exception as e:
        print(f"[ERROR] query_task: {e}")
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/v1/credit', methods=['GET'])
@require_api_key
def get_credit(api_key, key_info):
    """查询积分"""
    try:
        account, error = account_pool.get_available_account()
        if error:
            return jsonify({'error': error}), 503
        
        api = CapCutAPI(account['session_id'], account['did'])
        result = api.get_user_credit()
        
        if result.get('error'):
            return jsonify({'error': 'CapCut API Error', 'details': result}), 500
        
        return jsonify({
            'success': True,
            'account_id': account['id'],
            'account_email': account['email'],
            'credit_info': result
        })
        
    except Exception as e:
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/v1/credit/receive', methods=['POST'])
@require_api_key
def receive_credit(api_key, key_info):
    """领取每日积分"""
    try:
        account, error = account_pool.get_available_account()
        if error:
            return jsonify({'error': error}), 503
        
        api = CapCutAPI(account['session_id'], account['did'])
        result = api.credit_receive()
        
        if result.get('error'):
            return jsonify({'error': 'CapCut API Error', 'details': result}), 500
        
        return jsonify({
            'success': True,
            'account_id': account['id'],
            'account_email': account['email'],
            'receive_result': result
        })
        
    except Exception as e:
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

# ======================================================================
# OpenAI 兼容：模型列表
# ======================================================================

@app.route('/v1/models', methods=['GET'])
@require_api_key
def list_models(api_key, key_info):
    """返回可用模型列表（OpenAI 兼容格式），动态读取 CapCut 配置"""
    try:
        # 取一个可用账号来查询配置
        account, error = account_pool.get_available_account()
        if error:
            return jsonify({'error': {'message': error, 'type': 'service_unavailable'}}), 503

        api = CapCutAPI(account['session_id'], account['did'])
        cfg = api.get_common_config()

        models = []
        if isinstance(cfg, dict) and cfg.get('ret') == '0':
            model_list = (cfg.get('data') or {}).get('model_list') or []
            now_ts = int(time.time())
            for idx, m in enumerate(model_list):
                model_id = m.get('model_req_key') or m.get('model_key') or m.get('model_name')
                if not model_id:
                    continue
                models.append({
                    'id': model_id,
                    'object': 'model',
                    'created': now_ts + idx,
                    'owned_by': 'capcut',
                    'capabilities': {'vision': False, 'image': True},
                    'name': m.get('model_name') or model_id,
                    'tip': m.get('model_tip', '')
                })
        else:
            # 回退：返回内置常用模型
            models = [
                {'id': 'high_aes_general_v30l:general_v3.0_18b', 'object': 'model', 'created': int(time.time()), 'owned_by': 'capcut', 'capabilities': {'vision': False, 'image': True}},
                {'id': 'high_aes_anime_v30l:anime_v3.0_18b', 'object': 'model', 'created': int(time.time())+1, 'owned_by': 'capcut', 'capabilities': {'vision': False, 'image': True}},
                {'id': 'high_aes_realistic_v30l:realistic_v3.0_18b', 'object': 'model', 'created': int(time.time())+2, 'owned_by': 'capcut', 'capabilities': {'vision': False, 'image': True}},
            ]

        return jsonify({'object': 'list', 'data': models})
    except Exception as e:
        print(f"[ERROR] list_models: {e}")
        return jsonify({'error': {'message': str(e), 'type': 'internal_error'}}), 500

# ==============================================================================
# 管理端点
# ==============================================================================

def require_admin(f):
    """管理员验证装饰器"""
    def decorated_function(*args, **kwargs):
        password = request.headers.get('X-Admin-Password')
        
        if password != ADMIN_PASSWORD:
            return jsonify({'error': 'Unauthorized'}), 401
        
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/admin/keys/generate', methods=['POST'])
@require_admin
def admin_generate_key():
    """生成新的 API Key"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'unknown')
        quota = data.get('quota', 1000)
        description = data.get('description', '')
        
        api_key = api_key_manager.generate_key(user_id, quota, description)
        
        return jsonify({
            'success': True,
            'api_key': api_key,
            'user_id': user_id,
            'quota': quota,
            'description': description
        })
        
    except Exception as e:
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

@app.route('/admin/keys/list', methods=['GET'])
@require_admin
def admin_list_keys():
    """列出所有 API Keys"""
    return jsonify({
        'success': True,
        'api_keys': api_key_manager.api_keys
    })

@app.route('/admin/accounts/list', methods=['GET'])
@require_admin
def admin_list_accounts():
    """列出所有账号"""
    accounts = account_db.get_all_accounts()
    stats = account_db.get_statistics()
    
    return jsonify({
        'success': True,
        'accounts': accounts,
        'statistics': stats,
        'pool_size': len(account_pool.account_list)
    })

@app.route('/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    """统计信息"""
    account_stats = account_db.get_statistics()
    
    return jsonify({
        'success': True,
        'platform': 'render',
        'accounts': account_stats,
        'account_pool': {
            'available': len(account_pool.account_list),
            'failed': len(account_pool.failed_accounts)
        },
        'api_keys': {
            'total': len(api_key_manager.api_keys),
            'active': len([k for k in api_key_manager.api_keys.values() if k['status'] == 'active'])
        }
    })

@app.route('/admin/force-save', methods=['POST'])
@require_admin
def admin_force_save():
    """强制保存所有数据"""
    try:
        api_key_manager.save_keys()
        account_db.save_database()
        return jsonify({'success': True, 'message': 'Data saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==============================================================================
# 优雅关闭
# ==============================================================================
import signal
import sys

def graceful_shutdown(signum, frame):
    """优雅关闭（保存数据）"""
    print("\n[INFO] 收到关闭信号，正在保存数据...")
    api_key_manager.save_keys()
    account_db.save_database()
    print("[INFO] 数据已保存，退出")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

# ==============================================================================
# 启动服务
# ==============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("CapCut API 服务端 - Render 平台版")
    print("=" * 70)
    print(f"端口: {PORT}")
    print(f"账号数量: {account_db.get_statistics()['total']}")
    print(f"账号池大小: {len(account_pool.account_list)}")
    print(f"API Keys: {len(api_key_manager.api_keys)}")
    print("=" * 70)
    
    # Render 会通过 Gunicorn 启动，这里仅用于本地测试
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)


