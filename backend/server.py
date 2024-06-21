from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message

# from datetime import timedelta
from io import BytesIO
from PIL import Image
from flask_cors import CORS
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
from flask_bcrypt import Bcrypt
import numpy as np
import tensorflow as tf
import os
from dotenv import load_dotenv
import uuid
import re
import random
import phonenumbers
from datetime import datetime, timedelta


# configuration for coffee disease detection model
UPLOAD_FOLDER = "uploads"
load_dotenv()

app = Flask(__name__)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
app.config["PORT"] = os.getenv("PORT")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = os.getenv("MAIL_PORT")
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS")
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")
# write a program

db = SQLAlchemy(app)
engine = create_engine("sqlite:///users.db")
Session = sessionmaker(bind=engine)
session = Session()
jwt = JWTManager(app)
mail = Mail(app)
CORS(app)
bcrypt = Bcrypt(app)
MODEL_PATH = "saved_models/coffee3.keras"
MODEL = tf.keras.models.load_model(MODEL_PATH)
AUTOENCODER_PATH = "autoencoder/autoencoder2.keras"
AUTOENCODER = tf.keras.models.load_model(AUTOENCODER_PATH)
CLASS_NAMES = ["Cerscospora", "Healthy", "Leaf rust", "Miner", "Phoma"]
threshold = 10
regional_threshold = 3


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phoneNumber = db.Column(db.String(13), unique=True, nullable=False)
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
        self.password = password
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


class PasswordResetCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __init__(self, code, expiration, user_id):
        self.code = code
        self.expiration = expiration
        self.user_id = user_id


class Disease(db.Model):
    id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), unique=True, primary_key=True, nullable=False)
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
    disease_name = db.Column(
        db.String(100), db.ForeignKey("disease.name"), nullable=False
    )

    def to_dict(self):
        disease = Disease.query.filter_by(name=self.disease_name).first()
        return {
            "user_id": self.user_id,
            "image_id": self.image_id,
            "disease_name": self.disease_name,
            "timestamp": self.timestamp,
            "region": self.region,
            "confidence": self.confidence,
            "description": disease.description if disease else None,
            "symptoms": disease.symptoms if disease else None,
            "treatment": disease.treatment if disease else None,
        }


class ImageProcessingController:
    @staticmethod
    def preprocess_image(image_bytes) -> np.ndarray:
        image = Image.open(BytesIO(image_bytes)).convert("RGB")
        image = image.resize((128, 128))
        image_array = np.array(image) / 255.0
        return tf.expand_dims(image_array, 0)


class DatabaseHandler:
    def __init__(self, session):
        self.session = session

    def fetch_report_disease_counts(self):
        return (
            self.session.query(
                Report.region, Report.disease_name, func.count(Report.id)
            )
            .group_by(Report.region, Report.disease_name)
            .all()
        )

    def fetch_report_region_counts(self):
        return (
            self.session.query(Report.region, func.count(Report.region))
            .group_by(Report.region)
            .all()
        )

    def fetch_report_count(self):
        return self.session.query(Report).count()

    def fetch_report_regional_disease_counts(self):
        return (
            self.session.query(
                Report.disease_name, Report.region, func.count(Report.id)
            )
            .group_by(Report.disease_name, Report.region)
            .all()
        )

    def add_report(self, report):
        self.session.add(report)
        self.session.commit()


class DiseaseClassification:
    def __init__(self, imageProcessingController):
        self.imageProcessingController = imageProcessingController
        self.classificationResults = None
        self.disease = None

    def is_anomaly(self, img):
        reconstructed_img = AUTOENCODER.predict(img)
        reconstruction_error = tf.reduce_mean(tf.square(img - reconstructed_img))
        anomaly_threshold = 0.0009
        return reconstruction_error > anomaly_threshold

    def classify_disease(self, image_bytes):
        preprocessed_image = self.imageProcessingController.preprocess_image(
            image_bytes
        )
        if self.is_anomaly(preprocessed_image):
            classified_disease = "Anomaly"
            confidence = "0.0"
            return classified_disease, confidence
        else:
            predictions = MODEL.predict(preprocessed_image)
            max_prob = np.max(predictions[0])
            if max_prob >= 0.5:
                classified_disease = CLASS_NAMES[np.argmax(predictions[0])]
                confidence = round(100 * max_prob, 2)
                return classified_disease, confidence
            else:
                classified_disease = "Anomaly"
                confidence = round(100 * max_prob, 2)
                return classified_disease, confidence

    # def generate_report(self, classification_results, disease):
    #     self.classificationResults = classification_results
    #     self.disease = disease
    #     if classification_results == disease.name:
    #         report = {
    #             "disease": disease.name,
    #             "description": disease.description,
    #             "symptoms": disease.symptoms,
    #             "treatment": disease.treatment,
    #         }
    #     return report

    # def log_classification_event(self, log):
    #     print("Classification Event Log:", log)
    #     return log


class DataAnalysis:
    def __init__(self, database_handler):
        self.database_handler = database_handler
        self.result = {}

    def analyze_data(self):
        disease_counts = self.database_handler.fetch_report_disease_counts()
        region_counts = self.database_handler.fetch_report_region_counts()
        total_reports = self.database_handler.fetch_report_count()
        regional_disease_counts = (
            self.database_handler.fetch_report_regional_disease_counts()
        )

        self.result["total_reports"] = total_reports
        self.result["count_by_disease"] = self._count_by_disease(disease_counts)
        self.result["count_by_region"] = self._count_by_region(region_counts)
        self.result["prevalence_per_region"] = self._prevalence_per_region(
            regional_disease_counts
        )

        return self.result

    def _count_by_disease(self, disease_counts):
        disease_aggregate = {}
        for region, disease_name, count in disease_counts:
            if disease_name == "Healthy":
                continue
            else:
                if disease_name not in disease_aggregate:
                    disease_aggregate[disease_name] = 0
                disease_aggregate[disease_name] += count

        count_by_disease = []
        for disease_name, count in disease_aggregate.items():
            result = {
                "disease_name": disease_name,
                "count": count,
                "epidemic": True if count > threshold else False,
            }
            count_by_disease.append(result)
        return count_by_disease

    def _count_by_region(self, region_counts):
        region_aggregate = {}
        for region, count in region_counts:
            if region not in region_aggregate:
                region_aggregate[region] = 0
            region_aggregate[region] += count
        count_by_region = []
        for region, count in region_aggregate.items():
            result = {
                "region": region,
                "count": count,
                "epidemic": True if count > threshold else False,
            }
            count_by_region.append(result)
        return count_by_region

    def _prevalence_per_region(self, regional_disease_counts):
        prevalence_data = {}
        for disease_name, region, count in regional_disease_counts:
            if disease_name == "Healthy":
                continue
            else:
                if disease_name not in prevalence_data:
                    prevalence_data[disease_name] = []
                prevalence_data[disease_name].append({"region": region, "count": count})
        return prevalence_data


def send_reset_email(user_email, code):
    msg = Message("Password Reset Request", recipients=[user_email])
    msg.body = f"Please use the following 6 digit code  to reset your password: {code}"
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
        hashed_password = bcrypt.generate_password_hash(password)
        if is_strong_password(password):
            new_user = User(
                firstName,
                lastName,
                email,
                hashed_password,
                phoneNumber,
                zone,
                region,
                occupation,
            )
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "User created successfully"}), 201
        else:
            return jsonify({"message": "Invalid Password"}), 400
    else:
        return jsonify({"message": "Invalid Email"}), 400


def is_valid_email(email):
    # RegEx pattern for email validation
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def is_strong_password(password):
    # RegEx pattern for strong password validation
    pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password) is not None


@app.route("/login", methods=["POST"], endpoint="login")
def login():
    email = request.json["email"]
    password = request.json["password"]
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(
            identity=user.id, additional_claims={"email": email}
        )

        reportDiseaseCount = fetchData()
        diseasePrevalenceData = identifyEpidemicDisease(user, reportDiseaseCount)

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "user_id": user.id,
                    "email": user.email,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "phoneNumber": str(user.phoneNumber),
                    "zone": user.zone,
                    "region": user.region,
                    "occupation": user.occupation,
                    "Epidemic Disease": diseasePrevalenceData,
                }
            ),
            200,
        )
    return jsonify({"message": "Invalid username or password"}), 401


def fetchData():
    # Get the current date
    current_date = datetime.utcnow()
    date_30_days_ago = current_date - timedelta(days=30)
    report_disease_counts = (
        db.session.query(Report.region, Report.disease_name, func.count(Report.id))
        .filter(Report.timestamp >= date_30_days_ago)
        .group_by(Report.region, Report.disease_name)
        .all()
    )
    return report_disease_counts


def identifyEpidemicDisease(user, diseaseCounts):
    # Dictionary to store the prevalence data
    prevalence_data = []
    for region, disease_name, count in diseaseCounts:
        # print(count)
        if (
            user.region == region
            and count > regional_threshold
            and disease_name != "Healthy"
        ):
            updates = {
                "disease_name": disease_name,
                "count": count,
                "epidemic": True,
            }
            prevalence_data.append(updates)
        else:
            continue
    return prevalence_data


@app.route("/forgot-password", methods=["POST"], endpoint="forgot_password")
def forgot_password():
    email = request.json["email"]

    if is_valid_email(email):
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            reset_code = random.randint(100000, 999999)
            expiration_time = datetime.now() + timedelta(hours=1)
            passwordResetData = PasswordResetCode.query.filter_by(
                user_id=existing_user.id
            ).first()
            if passwordResetData:
                passwordResetData.code = str(reset_code)
                passwordResetData.expiration = expiration_time
                db.session.commit()
            else:
                password_reset_Code = PasswordResetCode(
                    code=str(reset_code),
                    expiration=expiration_time,
                    user_id=existing_user.id,
                )
                db.session.add(password_reset_Code)
                db.session.commit()
            print(f"password Reset {reset_code}")
            send_reset_email(email, reset_code)
            return (
                jsonify({"message": "Reset code has been sent to your email"}),
                201,
            )
        return jsonify({"message": "Invalid email address"}), 404
    return jsonify({"message": "Invalid form data"}), 400


@app.route("/reset-password", methods=["POST"], endpoint="reset_password")
def reset_password():
    reset_code = request.json["code"]
    if not reset_code.isdigit() or len(reset_code) != 6:
        return jsonify({"error": "Reset code must be exactly 6 digits"}), 400

    else:
        resetCode = PasswordResetCode.query.filter_by(code=reset_code).first()
        password = request.json["password"]
        if resetCode:
            print(f"expiration {resetCode.expiration }")
            print(f"now {datetime.now()}")
            if resetCode.expiration > datetime.now():
                user_id = resetCode.user_id
                print(f"user code {resetCode.user_id}")
                user = User.query.get(user_id)
                if user:
                    if is_strong_password(password):
                        user.password = bcrypt.generate_password_hash(password)
                        db.session.commit()
                        return jsonify({"message": "Password reset successful"}), 201
                    else:
                        return jsonify({"message": "Invalid Password"}), 400
                else:
                    return jsonify({"message": "User not found"}), 401
            else:
                return jsonify({"message": "The code has expired"}), 401
        else:
            return jsonify({"message": "Invalid code"}), 400


@app.route("/change-password", methods=["POST"], endpoint="change_password")
@jwt_required()
def reset_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    oldPassowrd = request.json["oldPassword"]
    if bcrypt.check_password_hash(user.password, oldPassowrd):
        newPassword = request.json["newPassword"]
        if is_strong_password(newPassword):
            user.password = bcrypt.generate_password_hash(newPassword)
            db.session.commit()
            return jsonify({"message": "Password changed successful"}), 201
        else:
            return jsonify({"message": "Invalid Password"}), 400
    else:
        return jsonify({"message": "Old password is incorrect"}), 400


@app.route("/users", methods=["GET"], endpoint="get_users")
def get_users():
    users = User.query.all()
    user_list = []

    for user in users:
        user_data = {}
        reports = Report.query.filter_by(user_id=user.id).all()
        print(f"all reports{reports}")
        user_data["user_id"] = user.id
        user_data["firstName"] = user.firstName
        user_data["lastName"] = user.lastName
        user_data["email"] = user.email
        user_data["phoneNumber"] = str(user.phoneNumber)
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
    print(reports)
    if user:
        user_data = {}
        user_data["user_id"] = user.id
        user_data["firstName"] = user.firstName
        user_data["lastName"] = user.lastName
        user_data["email"] = user.email
        user_data["phoneNumber"] = str(user.phoneNumber)
        user_data["zone"] = user.zone
        user_data["region"] = user.region
        user_data["occupation"] = user.occupation
        user_data["report"] = [report.to_dict() for report in reports]
        return jsonify(user_data), 200
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
        return jsonify({"message": "User deleted successfully"}), 201
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
        return jsonify({"error": "No selected Image"}), 400
    image_bytes = image_file.read()
    image_processing_controller = ImageProcessingController()

    image_id, filename = save_image(image_file)
    disease_classifier = DiseaseClassification(image_processing_controller)
    classified_disease, confidence = disease_classifier.classify_disease(image_bytes)
    if classified_disease == "Anomaly":
        return jsonify(
            {"class": str(classified_disease), "confidence": str(confidence)}
        )

    # Create a new report instance
    else:
        print(f"found disease {classified_disease}")
        # Fetch disease data from the database
        disease = Disease.query.filter_by(name=classified_disease).first()
        current_time = datetime.utcnow()
        report = Report(
            user_id=user_id,
            image_id=os.path.join(image_id + "_" + filename),
            timestamp=current_time,
            region=user.region,
            confidence=float(confidence),
            disease_name=disease.name,
        )

        # Add the report to the database
        db.session.add(report)
        db.session.commit()

        response_data = {
            "disease_name": disease.name,
            "timestamp": current_time,
            "confidence": str(confidence),
            "region": user.region,
            "description": disease.description,
            "symptoms": disease.symptoms,
            "treatment": disease.treatment,
        }
        return jsonify(response_data), 200


def save_image(image_file):
    image_id = str(uuid.uuid4())
    # saving image file
    filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_id + "_" + filename)
    image_file.save(image_path)
    return image_id, filename


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
        database_handler = DatabaseHandler(db.session)
        data_analysis = DataAnalysis(database_handler)
        analysis_result = data_analysis.analyze_data()
        print(analysis_result)
        #  Calculate the average confidence
        average_confidence = db.session.query(func.avg(Report.confidence)).scalar()

        # Convert the average confidence to a float
        average_confidence = (
            float(average_confidence) if average_confidence is not None else 0.0
        )

        print(f"Average Confidence: {average_confidence}")
        return (
            jsonify(
                {
                    "Total disease Report": analysis_result,
                    "Average Confidence": average_confidence,
                }
            ),
            200,
        )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
