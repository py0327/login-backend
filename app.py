from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta
import os
from functools import wraps

# 初始化应用
app = Flask(__name__)
CORS(app)

# 配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-123')  # 建议生产环境用强密码
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = True  # 生产环境请设为 False

# 初始化数据库
db = SQLAlchemy(app)

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(200), default='')  # 存储头像路径
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        """验证密码"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# 应用启动前钩子：创建数据库表和上传目录
@app.before_first_request
def setup_environment():
    # 创建数据库表（如果不存在）
    db.create_all()
    print("✅ 数据库表已创建/检查完毕")
    
    # 创建头像上传目录
    upload_dir = 'uploads'
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        print(f"✅ 创建上传目录：{upload_dir}")

# JWT 验证装饰器
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
        
        if not token:
            return jsonify({'message': 'Token 缺失!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': '用户不存在!'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token 过期!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': '无效 Token!'}), 401
        
        return f(current_user, *args, **kwargs)

# 生成 JWT 令牌
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# ------------------------
# 核心接口定义
# ------------------------

# 注册接口（兼容 account/phone 和 username 参数）
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # 支持手机号（account）或用户名（username）注册
    username = data.get('username') or data.get('account')
    password = data.get('password')
    avatar = data.get('avatar', '')  # 头像路径（由上传接口返回）
    phone = data.get('account')  # 保留手机号字段（如有需要）
    
    # 基础校验
    if not username or not password:
        return jsonify({
            'message': '用户名/手机号和密码为必填项',
            'code': 400
        }), 400
    
    # 用户名长度校验（示例：限制 3-20 位）
    if len(username) < 3 or len(username) > 20:
        return jsonify({
            'message': '用户名长度需在 3-20 位之间',
            'code': 400
        }), 400
    
    # 密码强度校验（示例：至少 6 位）
    if len(password) < 6:
        return jsonify({
            'message': '密码至少 6 位',
            'code': 400
        }), 400
    
    # 检查用户名/手机号唯一性
    if User.query.filter_by(username=username).first():
        return jsonify({
            'message': '用户名/手机号已存在',
            'code': 409
        }), 409
    
    # 加密密码
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # 创建用户
    new_user = User(
        username=username,
        password_hash=password_hash,
        avatar=avatar,
    )
    
    try:
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
        db.session.rollback()
        print(f"注册失败：{str(e)}")
        return jsonify({
            'message': '注册失败，请重试',
            'code': 500,
            'error': str(e)
        }), 500

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('username') or data.get('account')  # 支持用户名或手机号登录
    password = data.get('password')
    
    if not identifier or not password:
        return jsonify({
            'message': '请输入用户名/手机号和密码',
            'code': 400
        }), 400
    
    # 优先按手机号查询，若无则按用户名查询
    user = User.query.filter_by(username=identifier).first() or User.query.filter_by(account=identifier).first()
    
    if not user or not user.check_password(password):
        return jsonify({
            'message': '账号或密码错误',
            'code': 401
        }), 401
    
    # 生成令牌
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

# 头像上传接口（支持小程序上传）
@app.route('/api/upload/avatar', methods=['POST'])
def upload_avatar():
    try:
        # 检查是否有文件上传
        if 'file' not in request.files:  # 小程序默认字段为 'file'
            return jsonify({
                'message': '请选择头像文件',
                'code': 400
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'message': '请选择有效文件',
                'code': 400
            }), 400
        
        # 生成唯一文件名（避免重名）
        ext = file.filename.split('.')[-1] if '.' in file.filename else 'png'
        filename = f"avatar_{uuid.uuid4().hex}.{ext}"
        upload_path = os.path.join('uploads', filename)
        
        # 保存文件（生产环境建议使用云存储，如阿里云 OSS）
        file.save(upload_path)
        
        # 返回可访问的 URL（示例：假设域名+/uploads/文件名，需根据实际部署调整）
        # 若使用云存储，此处应返回云存储的 URL
        avatar_url = f'/uploads/{filename}' if os.environ.get('ENV') == 'development' else f'https://your-domain.com/uploads/{filename}'
        
        return jsonify({
            'message': '上传成功',
            'code': 200,
            'path': avatar_url  # 前端可将此路径存入用户信息
        }), 200
    
    except Exception as e:
        print(f"头像上传失败：{str(e)}")
        return jsonify({
            'message': '上传失败，请重试',
            'code': 500,
            'error': str(e)
        }), 500

# ------------------------
# 其他接口（示例）
# ------------------------

# 获取用户信息
@app.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    if current_user.id != user_id:
        return jsonify({
            'message': '权限不足',
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

# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'message': '资源未找到',
        'code': 404
    }), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        'message': '服务器内部错误',
        'code': 500
    }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
