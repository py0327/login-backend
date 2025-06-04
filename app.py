from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta
import os
from functools import wraps

# 初始化 Flask 应用
app = Flask(__name__)
# 配置跨域，生产环境可限制 origins
CORS(app, origins="*")  

# 配置项，生产环境建议通过环境变量设置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-123')  # 生产环境用强随机密钥
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///database.db'
)  # 优先从环境变量取数据库地址，默认用 SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭不必要的追踪，提升性能
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')  # 调试模式，生产环境设为 False

# 初始化 SQLAlchemy 数据库对象
db = SQLAlchemy(app)

# 定义用户数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # 用户名，唯一
    password_hash = db.Column(db.String(120), nullable=False)  # 加密后的密码
    avatar = db.Column(db.String(200), default='')  # 头像路径，默认空
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 注册时间

    def check_password(self, password):
        """验证密码，将明文密码加密后与数据库中存储的哈希值比对"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# JWT 验证装饰器，用于保护需要登录的接口
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # 从请求头中获取 Authorization 字段，提取 token
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else None
        
        if not token:
            return jsonify({'message': 'Token 缺失，访问被拒绝'}), 401
        
        try:
            # 解码 token，验证有效性
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': '用户不存在，Token 无效'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token 已过期，请重新登录'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': '无效的 Token，请重新登录'}), 401
        
        # 将当前用户对象传递给视图函数
        return f(current_user, *args, **kwargs)
    return decorated

# 生成 JWT 令牌的函数
def generate_token(user_id):
    """根据用户 ID 生成包含用户 ID 和过期时间的 JWT 令牌"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)  # 令牌 24 小时后过期
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# 注册接口，处理用户注册逻辑
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'message': '请求数据为空，请检查请求体'}), 400
    
    # 兼容获取用户名，优先取 username，也可通过 account 传递（根据前端需求调整）
    username = data.get('username') or data.get('account')
    password = data.get('password')
    avatar = data.get('avatar', '')  # 头像路径，选填，默认空字符串
    # 可扩展其他字段，如昵称、性别等，此处可根据实际需求添加
    
    # 基础校验
    if not username or not password:
        return jsonify({
            'message': '用户名和密码为必填项，请补充完整',
            'code': 400
        }), 400
    
    # 用户名长度校验（示例：3-20 个字符）
    if len(username) < 3 or len(username) > 20:
        return jsonify({
            'message': '用户名长度需在 3-20 个字符之间',
            'code': 400
        }), 400
    
    # 密码强度校验（示例：至少 6 个字符）
    if len(password) < 6:
        return jsonify({
            'message': '密码长度至少需要 6 个字符',
            'code': 400
        }), 400
    
    # 检查用户名是否已存在
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({
            'message': '该用户名已被注册，请更换其他用户名',
            'code': 409
        }), 409
    
    # 加密密码
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # 创建新用户对象
    new_user = User(
        username=username,
        password_hash=password_hash,
        avatar=avatar
    )
    
    try:
        # 将新用户添加到数据库并提交
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'message': '注册成功',
            'code': 201,
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'created_at': new_user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }), 201
    except Exception as e:
        # 发生异常时回滚事务，避免数据库不一致
        db.session.rollback()
        app.logger.error(f"注册失败，异常信息：{str(e)}")
        return jsonify({
            'message': '注册失败，请稍后重试',
            'code': 500,
            'error': str(e)
        }), 500

# 登录接口，处理用户登录逻辑
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': '请求数据为空，请检查请求体'}), 400
    
    # 支持通过 username 或自定义的 account 字段登录，根据实际前端传参调整
    identifier = data.get('username') or data.get('account')
    password = data.get('password')
    
    if not identifier or not password:
        return jsonify({
            'message': '请输入用户名/账号和密码',
            'code': 400
        }), 400
    
    # 查询用户，先按 username 查，再按可能的其他标识查（可扩展逻辑）
    user = User.query.filter_by(username=identifier).first()
    
    if not user or not user.check_password(password):
        return jsonify({
            'message': '账号或密码错误，请检查后重新输入',
            'code': 401
        }), 401
    
    # 生成 JWT 令牌
    token = generate_token(user.id)
    return jsonify({
        'message': '登录成功',
        'code': 200,
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

# 头像上传接口，处理文件上传逻辑
@app.route('/api/upload/avatar', methods=['POST'])
def upload_avatar():
    try:
        # 检查是否有文件上传，前端需用 'file' 作为文件名（如 wx.uploadFile 的 name 参数）
        if 'file' not in request.files:
            return jsonify({
                'message': '请选择要上传的头像文件',
                'code': 400
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'message': '请选择有效的文件进行上传',
                'code': 400
            }), 400
        
        # 生成唯一文件名，避免重复
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'png'
        unique_filename = f"avatar_{uuid.uuid4().hex}.{file_extension}"
        upload_folder = 'uploads'
        # 确保上传目录存在
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        upload_path = os.path.join(upload_folder, unique_filename)
        
        # 保存文件到服务器（生产环境建议使用云存储，如 AWS S3、阿里云 OSS 等）
        file.save(upload_path)
        
        # 构建可访问的文件路径，生产环境需配置正确的域名或 CDN 地址
        # 这里简单处理，实际要根据部署情况调整，比如用 nginx 映射或云存储公网地址
        avatar_url = f'/uploads/{unique_filename}' if app.config['DEBUG'] else f'https://your-domain.com/uploads/{unique_filename}'
        
        return jsonify({
            'message': '头像上传成功',
            'code': 200,
            'path': avatar_url  # 返回给前端，用于存储到用户信息中
        }), 200
    except Exception as e:
        app.logger.error(f"头像上传失败，异常信息：{str(e)}")
        return jsonify({
            'message': '头像上传失败，请稍后重试',
            'code': 500,
            'error': str(e)
        }), 500

# 获取用户信息接口，需登录后访问，且只能查看自己的信息
@app.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    # 校验当前登录用户是否有权限访问（只能访问自己的信息）
    if current_user.id != user_id:
        return jsonify({
            'message': '没有权限访问该用户信息',
            'code': 403
        }), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'message': '用户不存在',
            'code': 404
        }), 404
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

# 错误处理，统一返回 JSON 格式的错误信息
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'message': '请求的资源未找到',
        'code': 404
    }), 404

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"服务器内部错误：{str(error)}")
    return jsonify({
        'message': '服务器内部错误，请稍后重试',
        'code': 500
    }), 500

# 新增数据库和上传目录初始化命令，通过 Flask CLI 执行（替代原 before_first_request）
@app.cli.command("init-db")
def init_db():
    """
    初始化数据库表和上传目录的命令，可通过以下方式执行：
    - 本地开发：flask init-db（需激活虚拟环境，确保安装了依赖）
    - Railway 控制台：进入服务的 Shell，执行 python -m flask init-db
    """
    with app.app_context():
        db.create_all()  # 创建数据库表（如果不存在）
        upload_folder = 'uploads'
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)  # 创建上传目录
        print("✅ 数据库表和上传目录已成功初始化")

if __name__ == '__main__':
    # 获取端口，优先从环境变量取，默认 5000
    port = int(os.environ.get('PORT', 5000))
    # 启动应用，生产环境建议使用 Gunicorn 等 WSGI 服务器，此处为开发便捷
    app.run(host='0.0.0.0', port=port)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
