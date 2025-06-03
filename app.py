from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
from functools import wraps

# 初始化应用
app = Flask(__name__)
CORS(app)

# 配置（使用SQLite作为默认数据库）
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
db = SQLAlchemy(app)

# 数据模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# JWT 验证装饰器
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # 从请求头中获取 token
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
        
        if not token:
            return jsonify({'message': 'Token missing!'}), 401
        
        try:
            # 解码 token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
            
            if not current_user:
                return jsonify({'message': 'User not found!'}), 404
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# 生成 JWT
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
    
    # 验证输入
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required!'}), 400
    
    username = data['username']
    password = data['password']
    avatar = data.get('avatar', '')
    
    # 检查用户名是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists!'}), 400
    
    # 加密密码
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # 创建新用户
    new_user = User(
        username=username,
        password_hash=password_hash,
        avatar=avatar
    )
    
    # 保存到数据库
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed!', 'error': str(e)}), 500

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required!'}), 400
    
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    # 生成 token
    token = generate_token(user.id)
    
    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

# 获取用户信息接口
@app.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    # 只有用户本人或管理员可以查看信息
    if current_user.id != user_id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'avatar': user.avatar,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }), 200

# 更新用户信息接口
@app.route('/api/user/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    if current_user.id != user_id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    data = request.get_json()
    
    if not data:
        return jsonify({'message': 'No data provided!'}), 400
    
    # 更新可选字段
    if 'username' in data:
        # 检查新用户名是否已存在
        if User.query.filter_by(username=data['username']).first() and data['username'] != user.username:
            return jsonify({'message': 'Username already exists!'}), 400
        user.username = data['username']
    
    if 'password' in data:
        user.password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    if 'avatar' in data:
        user.avatar = data['avatar']
    
    try:
        db.session.commit()
        return jsonify({'message': 'User updated successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Update failed!', 'error': str(e)}), 500

# 删除用户接口
@app.route('/api/user/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    if current_user.id != user_id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Delete failed!', 'error': str(e)}), 500

# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found!'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error!', 'error': str(error)}), 500

# 启动应用
if __name__ == '__main__':
    # 创建数据库表
    with app.app_context():
        db.create_all()
    # 生产环境由 gunicorn 启动，这里仅用于开发环境
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
