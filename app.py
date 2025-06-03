from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import jwt
from functools import wraps
from jwt import encode as jwt_encode

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wechat_app.db'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SECRET_KEY'] = '060327'  # 生产环境建议改为更安全的随机字符串
CORS(app)
db = SQLAlchemy(app)

# 数据库模型（使用前端的字段名：account, nickName, isMale）
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(11), unique=True, nullable=False)  # 手机号
    password_hash = db.Column(db.String(128), nullable=False)
    nickName = db.Column(db.String(50), nullable=False)  # 昵称
    description = db.Column(db.String(200))  # 个人描述
    isMale = db.Column(db.Integer, default=0)  # 性别（0=女，1=男）
    avatarPath = db.Column(db.String(200))  # 头像路径
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

# 头像上传接口
@app.route('/api/upload/avatar', methods=['POST'])
def upload_avatar():
    file = request.files['avatar']
    if not file or not allowed_file(file.filename):
        return jsonify({'error': '无效的文件'}), 400
    
    filename = f"avatar_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({'path': filename}), 200

# 注册接口（适配前端字段名）
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # 校验
    if not data.get('account') or len(data['account']) != 11:
        return jsonify({'error': '手机号格式错误'}), 400
    
    if User.query.filter_by(account=data['account']).first():
        return jsonify({'error': '手机号已注册'}), 400
    
    # 创建用户（直接使用前端字段名）
    user = User(
        account=data['account'],
        password=data['password'],
        nickName=data['nickName'],
        description=data.get('description', ''),
        isMale=data.get('isMale', 0),
        avatarPath=data.get('avatarPath')
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': '注册成功'}), 201

# ---------------- 新增登录功能 ----------------

# 生成JWT令牌
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)  # 令牌有效期24小时
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# 验证JWT令牌
def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# 令牌验证装饰器
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': '令牌缺失', 'code': 401}), 401
        
        user_id = decode_token(token)
        if not user_id:
            return jsonify({'error': '无效令牌', 'code': 401}), 401
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在', 'code': 401}), 401
        
        return f(user, *args, **kwargs)
    return decorated

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    account = data.get('account')
    password = data.get('password')

    # 参数校验
    if not account or not password:
        return jsonify({'error': '请输入手机号和密码', 'code': 400}), 400

    # 查询用户
    user = User.query.filter_by(account=account).first()
    
    # 验证账号密码
    if not user or not user.verify_password(password):
        return jsonify({'error': '账号或密码错误', 'code': 401}), 401

    # 生成令牌并返回
    token = generate_token(user.id)
    
    # 构建用户信息（避免返回敏感字段）
    user_info = {
        'userId': user.id,
        'account': user.account,
        'nickName': user.nickName,
        'description': user.description,
        'isMale': user.isMale,
        'avatarPath': user.avatarPath,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return jsonify({
        'code': 200,
        'message': '登录成功',
        'token': token,
        'user': user_info
    }), 200

# 获取用户信息接口
@app.route('/api/user/info', methods=['GET'])
@token_required
def get_user_info(user):
    return jsonify({
        'code': 200,
        'message': '获取成功',
        'user': {
            'userId': user.id,
            'account': user.account,
            'nickName': user.nickName,
            'description': user.description,
            'isMale': user.isMale,
            'avatarPath': user.avatarPath,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

# 工具函数
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# 启动
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)