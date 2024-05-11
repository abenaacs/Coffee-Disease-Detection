from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.utils import secure_filename
from wtforms import Form, StringField, PasswordField, validators
import os
import uuid
import re

# configuration for coffee disease detection model

UPLOAD_FOLDER = "uploads"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = ""
app.config["JWT_SECRET_KEY"] = ""
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
db = SQLAlchemy(app)
jwt = JWTManager(app)

with app.app_context():

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(100), unique=True, nullable=False)
        email = db.Column(db.String(100), unique=True, nullable=False)
        password = db.Column(db.String(100), nullable=False)

        def __init__(self, username, email, password):
            self.username = username
            self.email = email
            self.password = generate_password_hash(password)

    class Disease(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), unique=True, nullable=False)
        description = db.Column(db.Text, nullable=False)
        symptoms = db.Column(db.Text, nullable=False)
        treatment = db.Column(db.Text, nullable=False)

        def __init__(self, name, description, symptoms, treatment):
            self.name = name
            self.description = description
            self.symptoms = symptoms
            self.treatment = treatment

    class Report(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
        image_id = db.Column(db.String(100), nullable=False)
        disease_name = db.Column(db.String(100), nullable=False)
        description = db.Column(db.Text, nullable=False)
        symptoms = db.Column(db.Text, nullable=False)
        treatment = db.Column(db.Text, nullable=False)

        def __init__(
            self, user_id, image_id, disease_name, description, symptoms, treatment
        ):
            self.user_id = user_id
            self.image_id = image_id
            self.disease_name = disease_name
            self.description = description
            self.symptoms = symptoms
            self.treatment = treatment

    def is_valid_email(email):
        # RegEx pattern for email validation
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        return re.match(pattern, email) is not None

    def is_strong_password(password):
        # RegEx pattern for strong password validation
        pattern = (
            r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        )
        return re.match(pattern, password) is not None

    @app.route("/users", methods=["POST"], endpoint="create_user")
    def create_user():

        username = request.json["username"]
        email = request.json["email"]
        password = request.json["password"]

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 400
        if is_valid_email(email):
            if is_strong_password(password):
                new_user = User(username, email, password)
                db.session.add(new_user)
                db.session.commit()
                return jsonify({"message": "User created successfully"}), 200
            else:
                return jsonify({"message": "Invalid Password"}), 400
        else:
            return jsonify({"message": "Invalid Email"}), 400

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

    @app.route("/coffee/detection", methods=["POST"], endpoint="coffee_detection")
    @jwt_required()
    def coffee_detection():
        user_id = get_jwt_identity()

        # user existence checking
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # image file inclusion checking
        if "image" not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        image_file = request.files["image"]
        if image_file.filename == "":
            return jsonify({"error": "Invalid image file"}), 400

        # unique ID for the image
        image_id = str(uuid.uuid4())

        # saving image file
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(
            app.config["UPLOAD_FOLDER"], image_id + "_" + filename
        )
        image_file.save(image_path)

        # Demo
        model_response = "No Disease Found"
        if model_response == "Inappropriate Image":
            return jsonify({"error": "Inappropriate image"}), 400

        if model_response == "No Disease Found":
            return jsonify({"message": "No disease found"}), 200

        # Fetch disease data from the database
        disease = Disease.query.filter_by(name=model_response).first()
        if not disease:
            return jsonify({"error": "Disease not found"}), 400

        # Create a new report instance
        report = Report(
            user_id=user_id,
            image_id=image_id,
            disease_name=model_response,
            description=disease.description,
            symptoms=disease.symptoms,
            treatment=disease.treatment,
        )

        # Add the report to the database
        db.session.add(report)
        db.session.commit()

        response_data = {
            "disease_name": disease.name,
            "description": disease.description,
            "symptoms": disease.symptoms,
            "treatment": disease.treatment,
        }

        return jsonify(response_data), 201


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
