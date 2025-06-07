# app.py (修改后)

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta
import os
from functools import wraps
from flask_migrate import Migrate
import cloudinary
import cloudinary.uploader

# 初始化 Flask 应用
app = Flask(__name__)
CORS(app, origins="*")  # 开发环境允许所有域名，生产环境建议限制为小程序域名

# 配置项
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-123')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///database.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')

# 配置 Cloudinary（替换为你的实际值）
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME', 'your_cloud_name'),
    api_key=os.environ.get('CLOUDINARY_API_KEY', 'your_api_key'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET', 'your_api_secret'),
    secure=True  # 使用 HTTPS
)

# 初始化数据库和迁移
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(200), default='')  # 存储 Cloudinary 图片 URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    isMale = db.Column(db.Integer, default=1)  # 性别（1=男，0=女）
    description = db.Column(db.String(200), default='')  # 用户简介

    def check_password(self, password):
        """验证密码"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

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
    return decorated

# 生成 JWT 令牌
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# 注册接口
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'message': '请求数据为空'}), 400
    
    username = data.get('username')
    password = data.get('password')
    avatar = data.get('avatar', '')
    nickName = data.get('nickName', username)
    isMale = data.get('isMale', 1)
    description = data.get('description', '')
    
    # 基本验证
    if not username or not password:
        return jsonify({'message': '用户名和密码不能为空'}), 400
    
    if len(username) < 3 or len(username) > 20:
        return jsonify({'message': '用户名长度应为 3-20 个字符'}), 400
    
    if len(password) < 6:
        return jsonify({'message': '密码长度至少为 6 个字符'}), 400
    
    # 检查用户名是否已存在
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': '用户名已存在'}), 409
    
    # 加密密码
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # 创建新用户
    new_user = User(
        username=username,
        password_hash=password_hash,
        avatar=avatar,
        isMale=isMale,
        description=description
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'code': 201,  # 添加状态码字段与前端保持一致
            'message': '注册成功',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'avatar': new_user.avatar,
                'created_at': new_user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'code': 500, 'message': '注册失败', 'error': str(e)}), 500

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'code': 400, 'message': '请求数据为空'}), 400
    
    # 兼容前端的 identifier 字段
    identifier = data.get('identifier') or data.get('username')
    password = data.get('password')
    
    if not identifier or not password:
        return jsonify({'code': 400, 'message': '用户名和密码不能为空'}), 400
    
    # 支持用户名或手机号登录
    user = User.query.filter_by(username=identifier).first()
    
    if not user or not user.check_password(password):
        return jsonify({'code': 401, 'message': '用户名或密码错误'}), 401
    
    token = generate_token(user.id)
    
    return jsonify({
        'code': 200,  # 添加状态码字段与前端保持一致
        'message': '登录成功',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'isMale': user.isMale,
            'description': user.description,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

# 头像上传接口（使用 Cloudinary）
@app.route('/api/upload/avatar', methods=['POST'])
def upload_avatar():
    if 'file' not in request.files:
        return jsonify({'code': 400, 'message': '未上传文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'code': 400, 'message': '文件名不能为空'}), 400
    
    try:
        # 上传到 Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            folder="your_app_name/avatars",  # 自定义文件夹，便于管理
            resource_type="image",
            format="jpg",  # 强制转换为 JPG 格式
            quality="auto:good",  # 自动优化图片质量
            transformation=[
                {"width": 300, "height": 300, "crop": "fill", "gravity": "face"}  # 裁剪为 300x300 人脸居中
            ]
        )
        
        return jsonify({
            'code': 200,
            'message': '上传成功',
            'path': upload_result['secure_url']  # 返回 HTTPS URL
        }), 200
    
    except Exception as e:
        return jsonify({'code': 500, 'message': '上传失败', 'error': str(e)}), 500

# 获取用户信息接口
@app.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    if current_user.id != user_id:
        return jsonify({'code': 403, 'message': '权限不足'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'code': 404, 'message': '用户不存在'}), 404
    
    return jsonify({
        'code': 200,
        'user': {
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'isMale': user.isMale,
            'description': user.description,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

# 健康检查接口
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'ok', 'message': '服务正常运行'}), 200

# 数据库初始化命令
@app.cli.command("init-db")
def init_db():
    """初始化数据库表"""
    with app.app_context():
        db.create_all()
        print("✅ 数据库表已初始化")

# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'code': 404, 'message': '资源未找到'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'code': 500, 'message': '服务器内部错误'}), 500

if __name__ == '__main__':
    # 使用 Gunicorn 时由环境变量控制，直接运行时使用默认值
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
