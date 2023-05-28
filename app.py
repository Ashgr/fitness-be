from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from flask_cors import CORS  # Import the CORS class

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SECRET_KEY'] = 'thisisasecret'

db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullName = db.Column(db.String(50))
    email = db.Column(db.String(50))
    content = db.Column(db.String(512))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    age = db.Column(db.Integer)
    height = db.Column(db.Float)
    weight = db.Column(db.Float)
    gender = db.Column(db.String(10))
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@auth.verify_password
def verify_password(email, password):
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        return user

@app.route('/api/users', methods=['POST'])
def create_user():
    user = User()
    print("====================+++",request.json.get('is_admin'))
    user.first_name = request.json.get('first_name')
    user.last_name = request.json.get('last_name')
    user.age = request.json.get('age')
    user.height = request.json.get('height')
    user.is_admin = request.json.get('is_admin')
    user.weight = request.json.get('weight')
    user.gender = request.json.get('gender')
    user.email = request.json.get('email')
    user.set_password(request.json.get('password'))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created"}), 201

@app.route('/api/users/<int:user_id>', methods=['GET'])
@auth.login_required
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify({
        'first_name': user.first_name,
        'last_name': user.last_name,
        'age': user.age,
        'height': user.height,
        'weight': user.weight,
        'gender': user.gender,
        'email': user.email
    })

@app.route('/api/users/<string:user_email>', methods=['PUT'])
def update_user(user_email):
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
    user.first_name = request.json.get('first_name', user.first_name)
    user.last_name = request.json.get('last_name', user.last_name)
    user.age = request.json.get('age', user.age)
    user.height = request.json.get('height', user.height)
    user.weight = request.json.get('weight', user.weight)
    user.gender = request.json.get('gender', user.gender)
    db.session.commit()
    return jsonify({"message": "User updated"})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@auth.login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    output = []
    for user in users:
        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'age': user.age,
            'height': user.height,
            'weight': user.weight,
            'gender': user.gender,
            'email': user.email,
            'is_admin':user.is_admin
            # for security reasons, you should not expose the password hash
        }
        output.append(user_data)
    return jsonify({'users': output})
    
@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    # Find the user by email
    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        # User authentication successful
        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'age': user.age,
            'height': user.height,
            'weight': user.weight,
            'gender': user.gender,
            'email': user.email,
        }
        return jsonify({'message': 'Login successful',"user":user_data}),200
    else:
        # User authentication failed
        return jsonify({'message': 'Invalid email or password'}),401


@app.route('/api/message', methods=['POST'])
def create_message():
    message = Message()
    message.fullName = request.json.get('fullName')
    message.email = request.json.get('email')
    message.content = request.json.get('message')

    db.session.add(message)
    db.session.commit()
    return jsonify({"message": "Message created"}), 201

@app.route('/api/messages', methods=['GET'])
def get_messages():
    messages = Message.query.all()
    output = []
    for message in messages:
        message_data = {
            'id': message.id,
            'fullName': message.fullName,
            'email': message.email,
            'message': message.content,
            # for security reasons, you should not expose the password hash
        }
        output.append(message_data)
    return jsonify(output)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
