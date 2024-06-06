from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    decode_token,
)
from jwt import InvalidTokenError
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from datetime import timedelta
from io import BytesIO
from PIL import Image
from flask_cors import CORS
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func

import numpy as np
import tensorflow as tf
import os
from dotenv import load_dotenv
import uuid
import re
import phonenumbers
import datetime


# configuration for coffee disease detection model
UPLOAD_FOLDER = "uploads"
load_dotenv()

app = Flask(__name__)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
app.config["PORT"]  = os.getenv("PORT")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = os.getenv("MAIL_PORT")
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS")
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")
# write a program

db = SQLAlchemy(app)
engine = create_engine(
    "sqlite:///users.db"
)  # Replace 'your_database_url' with the actual URL of your database
Session = sessionmaker(bind=engine)
session = Session()
jwt = JWTManager(app)
mail = Mail(app)
CORS(app)

MODEL = tf.keras.models.load_model("saved_models/cnn_model.keras")

CLASS_NAMES = ["Early Blight", "Late Blight", "Healthy"]
threshold = 10
regional_threshold = 3


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phoneNumber = db.Column(db.Integer, unique=True, nullable=False)
    zone = db.Column(db.String(100))
    region = db.Column(db.String(100))
    occupation = db.Column(db.String(100))

    def __init__(
        self,
        firstName,
        lastName,
        email,
        password,
        phoneNumber,
        zone,
        region,
        occupation,
    ):
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.password = generate_password_hash(password)
        self.phoneNumber = self.validate_phone_number(phoneNumber)
        self.zone = zone
        self.region = region
        self.occupation = occupation

    @staticmethod
    def validate_phone_number(phone_number):
        try:
            parsed_number = phonenumbers.parse(phone_number, None)
            if not phonenumbers.is_valid_number(parsed_number):
                raise ValueError("Invalid phone number")
            return phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.E164
            )
        except phonenumbers.phonenumberutil.NumberParseException:
            raise ValueError("Invalid phone number")


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(32), unique=True, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship(
        "User", backref=db.backref("password_reset_token", uselist=False)
    )


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
    timestamp = db.Column(db.DateTime, nullable=False)
    region = db.Column(db.String(100))
    confidence = db.Column(db.String(100), nullable=False)
    disease_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    symptoms = db.Column(db.Text, nullable=False)
    treatment = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "image_id": self.image_id,
            "disease_name": self.disease_name,
            "image-timestamp": self.timestamp,
            "region": self.region,
            "confidence": self.confidence,
            "description": self.description,
            "symptoms": self.symptoms,
            "treatment": self.treatment,
        }

def is_valid_email(email):
    # RegEx pattern for email validation
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def is_strong_password(password):
    # RegEx pattern for strong password validation
    pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password) is not None


def send_reset_email(user_email, token):
    reset_link = url_for("reset_password", token=token, _external=True)
    msg = Message("Password Reset Request", recipients=[user_email])
    msg.body = (
        f"Please click on the following link to reset your password: {reset_link}"
    )
    mail.send(msg)


@app.route("/register", methods=["POST"], endpoint="create_user")
def create_user():

    firstName = request.json["firstName"]
    lastName = request.json["lastName"]
    email = request.json["email"]
    password = request.json["password"]
    phoneNumber = request.json["phoneNumber"]
    zone = request.json["zone"]
    region = request.json["region"]
    occupation = request.json["occupation"]

    existing_user = User.query.filter_by(email=email).first()
    existing_phone = User.query.filter_by(phoneNumber=phoneNumber).first()
    if existing_user:
        return jsonify({"message": "Username already exists"}), 400
    if existing_phone:
        return jsonify({"message": "Phone number already exists"}), 400
    if is_valid_email(email):
        if is_strong_password(password):
            new_user = User(
                firstName,
                lastName,
                email,
                password,
                phoneNumber,
                zone,
                region,
                occupation,
            )
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "User created successfully"}), 200
        else:
            return jsonify({"message": "Invalid Password"}), 400
    else:
        return jsonify({"message": "Invalid Email"}), 400


@app.route("/login", methods=["POST"], endpoint="login")
def login():
    email = request.json["email"]
    password = request.json["password"]
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(
            identity=user.id, additional_claims={"email": email}
        )
        report_disease_counts = (
            db.session.query(Report.region, Report.disease_name, func.count(Report.id))
            .group_by(Report.region, Report.disease_name)
            .all()
        )

        # Dictionary to store the prevalence data
        prevalence_data = []
        for region, disease_name, count in report_disease_counts:
            print(count)
            if user.region == region and count > regional_threshold:
                updates = {
                    "disease_name": disease_name,
                    "count": count,
                    "epidemic": True,
                }
                prevalence_data.append(updates)
            else:
                continue

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "user_id": user.id,
                    "email": user.email,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "phoneNumber": user.phoneNumber,
                    "zone": user.zone,
                    "region": user.region,
                    "occupation": user.occupation,
                    "Epidemic Disease": prevalence_data,
                }
            ),
            200,
        )
    return jsonify({"message": "Invalid username or password"}), 401


@app.route("/forgot-password", methods=["POST"], endpoint="forgot_password")
@jwt_required()
def forgot_password():
    user_id = get_jwt_identity()
    email = request.json["email"]

    if is_valid_email(email):
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.id == user_id:
                reset_token = create_access_token(identity=existing_user.id)
                send_reset_email(email, reset_token)
                return (
                    jsonify({"message": "Reset token has been sent to your email"}),
                    201,
                )
            return jsonify({"message": "Access denied"}), 403
        return jsonify({"message": "Invalid email address"}), 404
    return jsonify({"message": "Invalid form data"}), 400


@app.route("/reset-password", methods=["POST"], endpoint="reset_password")
@jwt_required()
def reset_password():
    reset_token = request.json["token"]
    password = request.json["password"]
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    try:
        decoded_token = decode_token(reset_token)
        print(f"decoded token: {decoded_token}")
        if decoded_token["sub"] == user.id:
            user.password = generate_password_hash(password)
            db.session.commit()
            return jsonify({"message": "Password reset successful"}), 201
        else:
            return jsonify({"message": "Invalid user"}), 404
    except InvalidTokenError:
        return jsonify({"message": "Invalid reset token"}), 400
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route("/users", methods=["GET"], endpoint="get_users")
def get_users():
    users = User.query.all()
    user_list = []

    for user in users:
        user_data = {}
        reports = Report.query.filter_by(user_id=user.id).all()
        print(f"all reports{reports}")
        user_data["id"] = user.id
        user_data["firstName"] = user.firstName
        user_data["lastName"] = user.lastName
        user_data["phoneNumber"] = user.phoneNumber
        user_data["zone"] = user.zone
        user_data["region"] = user.region
        user_data["occupation"] = user.occupation
        user_data["report"] = [report.to_dict() for report in reports]
        user_list.append(user_data)
    return jsonify(user_list), 200


@app.route("/users/<int:user_id>", methods=["GET"], endpoint="get_user")
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({"message": "Access denied"}), 403
    user = User.query.get(user_id)
    reports = Report.query.filter_by(user_id=user_id).all()
    if user:
        user_data = {}
        user_data["id"] = user.id
        user_data["firstName"] = user.firstName
        user_data["lastName"] = user.lastName
        user_data["phoneNumber"] = user.phoneNumber
        user_data["zone"] = user.zone
        user_data["region"] = user.region
        user_data["occupation"] = user.occupation
        user_data["report"] = [report.to_dict() for report in reports]
        return jsonify(user_data), 201
    return jsonify({"message": "User not found"}), 404


@app.route("/users/<int:user_id>", methods=["PUT"], endpoint="update_user")
@jwt_required()
def update_user(user_id):
    current_user_id = get_jwt_identity()

    if current_user_id == user_id:
        user = User.query.get(current_user_id)
        if user:
            user.firstName = request.json["firstName"]
            user.lastName = request.json["lastName"]
            user.phoneNumber = request.json["phoneNumber"]
            user.zone = request.json["zone"]
            user.region = request.json["region"]
            user.occupation = request.json["occupation"]
            db.session.commit()
            return jsonify({"message": "User updated successfully"}), 201
        return jsonify({"message": "User Not found"}), 404
    return jsonify({"message": "Access denied"}), 403


@app.route("/users/<int:user_id>", methods=["DELETE"], endpoint="delete_user")
@jwt_required()
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


@app.route(
    "/coffee-disease-detection",
    methods=["POST"],
    endpoint="coffee_disease_detection",
)
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
    image_bytes = image_file.read()
    image = Image.open(BytesIO(image_bytes))
    image = image.resize((256, 256))

    image_array = np.array(image)
    img_batch = np.expand_dims(image_array, 0)
    predictions = MODEL.predict(img_batch)
    predicted_class = CLASS_NAMES[np.argmax(predictions[0])]
    confidence = np.max(predictions[0])

    # Anomaly detection threshold (adjust this value based on your requirements)
    anomaly_threshold = 0.3

    if confidence < anomaly_threshold:
        return jsonify({"message": "No disease found"}), 200
    else:
        image_id = str(uuid.uuid4())
        # saving image file
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(
            app.config["UPLOAD_FOLDER"], image_id + "_" + filename
        )
        image_file.save(image_path)
        if predicted_class == "":
            return jsonify("Invalid Image"), 400
        else:
            # Fetch disease data from the database
            disease = Disease.query.filter_by(name=predicted_class).first()
            current_time = datetime.datetime.now()

            # Create a new report instance
            report = Report(
                user_id=user_id,
                image_id=os.path.join(image_id + "_" + filename),
                timestamp=current_time,
                region=user.region,
                disease_name=predicted_class,
                confidence=float(confidence),
                description=disease.description,
                symptoms=disease.symptoms,
                treatment=disease.treatment,
            )

            # Add the report to the database
            db.session.add(report)
            db.session.commit()

            response_data = {
                "disease_name": predicted_class,
                "image_TimeStamp": current_time,
                "confidence": float(confidence),
                "region": user.region,
                "description": disease.description,
                "symptoms": disease.symptoms,
                "treatment": disease.treatment,
            }
            return jsonify(response_data), 200


@app.route(
    "/researcher-page",
    methods=["GET"],
    endpoint="researcher-page",
)
@jwt_required()
def researcher_page():
    user_id = get_jwt_identity()

    # user existence checking
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.occupation != "Researcher":
        return jsonify({"unauthorized user"}), 403
    else:
        report_disease_counts = (
            db.session.query(Report.disease_name, func.count(Report.disease_name))
            .group_by(Report.disease_name)
            .all()
        )
        # for disease_name, count in report_disease_counts:

        report_region_counts = (
            db.session.query(Report.region, func.count(Report.region))
            .group_by(Report.region)
            .all()
        )

        # Get the total count of reports
        report_count = Report.query.count()

        # Create an array tos tore the results
        count_by_disease = []

        # Iterate over the report counts and add them to the count_by_disease array
        for disease_name, count in report_disease_counts:
            result = {
                "disease_name": disease_name,
                "count": count,
                "epidemic": True if count > threshold else False,
            }
            count_by_disease.append(result)

        # Iterate over the report counts and add them to the count_by_region array
        count_by_region = []

        for region, count in report_region_counts:
            results = {"region": region, "count": count}
            count_by_region.append(results)

        report_regional_disease_counts = (
            db.session.query(Report.disease_name, Report.region, func.count(Report.id))
            .group_by(Report.disease_name, Report.region)
            .all()
        )
        print(f"reports regional disease {report_regional_disease_counts}")

        # Dictionary to store the prevalence data
        prevalence_data = {}
        for disease_name, region, count in report_regional_disease_counts:
            if disease_name not in prevalence_data:
                prevalence_data[disease_name] = []
            prevalence_data[disease_name].append({"region": region, "count": count}),

        return (
            jsonify(
                {
                    "Total disease Report": report_count,
                    "Count by disease": count_by_disease,
                    "Count by region": count_by_region,
                    "prevalency per region": prevalence_data,
                }
            ),
            200,
        )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # with app.app_context():
        #     sample_diseases = [
        #                         Disease(
        #                             name="Early Blight",
        #                             description="Early blight is a common fungal disease that affects potatoes, caused by the pathogen Alternaria solani. It typically appears during warm and humid weather conditions.",
        #                             symptoms="Dark brown to black lesions with concentric rings appear on the lower leaves of the potato plant.Lesions may have a target-like appearance with a dark center and lighter outer rings.As the disease progresses, the lesions may expand and affect more leaves, stems, and even the tubers.Infected tubers may develop shallow, dry, corky lesions that can rot during storage.",
        #                             treatment="Cultural practices play a crucial role in managing early blight. Here are some recommended methods:Crop rotation: Avoid planting potatoes or related crops in the same location for consecutive years. Proper spacing: Maintain adequate spacing between plants to improve air circulation and reduce humidity. Timely planting: Plant early-maturing potato varieties to minimize the period of susceptibility to the disease.Sanitation: Remove and destroy infected plant debris to prevent the spread of spores.Fungicides: In severe cases, fungicides containing active ingredients such as chlorothalonil, mancozeb, or copper-based products may be applied following the manufacturer's instructions. However, it's important to note that fungicides should be used judiciously and in accordance with local regulations.",
        #                         ),
        #                         Disease(
        #                             name="Late Blight",
        #                             description="Late blight is a devastating fungal disease caused by the pathogen Phytophthora infestans, which can affect both potatoes and tomatoes. It thrives in cool and wet conditions.",
        #                             symptoms="Initially, irregularly shaped, water-soaked lesions appear on the leaves, often starting from the tips.Lesions rapidly expand, turning brown or black and becoming surrounded by a pale green halo.In humid conditions, a whitish, fuzzy mold may develop on the underside of the leaves.Infected tubers show dark, firm lesions that can spread and cause rotting.",
        #                             treatment="Prompt action is essential to manage late blight effectively. Consider the following treatment methods:Fungicides: Due to the severity and rapid spread of late blight, chemical control with fungicides is often necessary. Consult with local agricultural authorities or extension services for approved fungicides and recommended application schedules.Cultural practices: Similar to early blight, cultural practices play a vital role in managing late blight. These include crop rotation, proper spacing, and removal of infected plant material.Resistant varieties: Planting potato varieties that have some level of resistance to late blight can help minimize the disease's impact.",
        #                         ),
        #                         Disease(
        #                             name = "Healthy",
        #                             description="This plant is healthy coffee plant",
        #                             symptoms = "No Symptoms",
        #                             treatment = "None"
        #                         )
        #                     ]
        #     for disease in sample_diseases:
        #         db.session.add(disease)

        #     # Commit the changes to the database
        #     db.session.commit()

    app.run(debug=True)
