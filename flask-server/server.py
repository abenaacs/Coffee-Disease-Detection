from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = ""
app.config["JWT_SECRET_KEY"] = ""  # Change this to a secure secret key
db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)


@app.route("/users", methods=["POST"], endpoint="create_user")
def create_user():
    username = request.json["username"]
    email = request.json["email"]
    password = request.json["password"]
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Username already exists"}), 400
    new_user = User(username, email, password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"})


@app.route("/login", methods=["POST"], endpoint="login")
def login():
    username = request.json["username"]
    password = request.json["password"]
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token})
    return jsonify({"message": "Invalid username or password"}), 401


@app.route("/users", methods=["GET"], endpoint="get_users")
@jwt_required
def get_users():
    users = User.query.all()
    user_list = []
    for user in users:
        user_data = {}
        user_data["id"] = user.id
        user_data["username"] = user.username
        user_data["email"] = user.email
        user_list.append(user_data)
    return jsonify(user_list)


@app.route("/users/<int:user_id>", methods=["GET"], endpoint="get_user")
@jwt_required
def get_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({"message": "Access denied"}), 403
    user = User.query.get(user_id)
    if user:
        user_data = {}
        user_data["id"] = user.id
        user_data["username"] = user.username
        user_data["email"] = user.email
        return jsonify(user_data)
    return jsonify({"message": "User not found"}), 404


@app.route("/users/<int:user_id>", methods=["PUT"], endpoint="update_user")
@jwt_required
def update_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({"message": "Access denied"}), 403
    user = User.query.get(user_id)
    if user:
        user.username = request.json["username"]
        user.email = request.json["email"]
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    return jsonify({"message": "User not found"}), 404


@app.route("/users/<int:user_id>", methods=["DELETE"], endpoint="delete_user")
@jwt_required
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({"message": "Access denied"}), 403
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    return jsonify({"message": "User not found"}), 404


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
