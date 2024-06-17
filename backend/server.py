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
from flask_bcrypt import Bcrypt
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
engine = create_engine(
    "sqlite:///users.db"
)  # Replace 'your_database_url' with the actual URL of your database
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
CLASS_NAMES = ["Cerscospora", "Leaf rust", "Miner", "Phoma", "Healthy"]
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
    confidence = db.Column(db.Float, nullable=False)
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


@app.route("/login", methods=["POST"], endpoint="login")
def login():
    email = request.json["email"]
    password = request.json["password"]
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
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
        user_data["user_id"] = user.id
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
        user_data["user_id"] = user.id
        user_data["firstName"] = user.firstName
        user_data["lastName"] = user.lastName
        user_data["phoneNumber"] = user.phoneNumber
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
        return jsonify({"error": "Invalid image file"}), 400
    image_bytes = image_file.read()
    image_array = read_file_as_image(image_bytes)
    img_batch = tf.expand_dims(image_array, 0)

    if is_anomaly(img_batch):
        return jsonify({"class": "Anomaly", "confidence": 0.0})
    else:
        image_id, filename = save_image(image_file)
        predicted_class, confidence = predict_image_class(img_batch)

        # Fetch disease data from the database
        disease = Disease.query.filter_by(name=predicted_class).first()
        current_time = datetime.datetime.now()

        # Create a new report instance
        report = Report(
            user_id=user_id,
            image_id=os.path.join(image_id + "_" + filename),
            timestamp=current_time,
            region=user.region,
            disease_name=disease.name,
            confidence=float(confidence),
            description=disease.description,
            symptoms=disease.symptoms,
            treatment=disease.treatment,
        )

        # Add the report to the database
        db.session.add(report)
        db.session.commit()

        response_data = {
            "disease_name": disease.name,
            "timeStamp": current_time,
            "confidence": float(confidence),
            "region": user.region,
            "description": disease.description,
            "symptoms": disease.symptoms,
            "treatment": disease.treatment,
        }
        return jsonify(response_data), 200


# Anomaly detection threshold
def is_anomaly(img):
    reconstructed_img = AUTOENCODER.predict(img)
    reconstruction_error = tf.reduce_mean(tf.square(img - reconstructed_img))
    anomaly_threshold = 0.009
    return reconstruction_error > anomaly_threshold


# Reading Image file
def read_file_as_image(data) -> np.ndarray:
    image = Image.open(BytesIO(data)).convert("RGB")
    image = image.resize((128, 128))
    imageArray = np.array(image) / 255.0
    return imageArray


# Predicting image class
def predict_image_class(img):
    # img_array = tf.expand_dims(img, 0)
    predictions = MODEL.predict(img)
    max_prob = np.max(predictions[0])
    if max_prob >= 0.5:
        predicted_class = CLASS_NAMES[np.argmax(predictions[0])]
        confidence = round(100 * max_prob, 2)
        return predicted_class, confidence
    else:
        return jsonify("Anomaly", round(100 * max_prob, 2)), 200


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
        # print(f"reports regional disease {report_regional_disease_counts}")

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
        #                             name="Cercospora",
        #                             description="Cercospora is a fungal disease that affects coffee plants. It is caused by the fungus Cercospora coffeicola. The disease is commonly known as 'Cercospora leaf spot' or 'coffee leaf spot.'",
        #                             symptoms="The disease primarily affects the leaves of the coffee plant. Initially, small yellow spots appear on the upper surface of the leaves. As the disease progresses, the spots enlarge and turn dark brown or black. The affected leaves may also develop a chlorotic halo around the spots. Severe infections can lead to premature defoliation of the coffee plant, reducing yields.",
        #                             treatment="Managing Cercospora involves a combination of cultural and chemical control methods. Cultural practices include maintaining proper plant spacing, providing adequate shade, and promoting good air circulation. Regular pruning to remove infected leaves and debris helps reduce disease spread. Fungicides can be used to control severe infections, but their application should be based on expert advice to minimize resistance development.",
        #                         ),
        #                         Disease(
        #                             name="Leaf Rust",
        #                             description="Leaf rust, caused by the fungus Hemileia vastatrix, is one of the most devastating coffee diseases worldwide. It primarily affects the leaves of coffee plants.",
        #                             symptoms="The disease manifests as small, yellow-orange powdery pustules on the undersides of the leaves. These pustules correspond to the fungal spore masses. As the infection progresses, the pustules turn dark brown or black. Infected leaves may eventually drop. Severe infections can lead to defoliation, reduced photosynthesis, and diminished yields.",
        #                             treatment="Managing leaf rust involves a combination of cultural practices and fungicide applications. Cultural methods include planting resistant coffee varieties, maintaining appropriate shade, and practicing good sanitation by removing and destroying infected leaves. Fungicides can be applied preventively or curatively, but their use should be based on expert advice to prevent resistance development.",
        #                         ),
        #                         Disease(
        #                             name="Miner",
        #                             description="The coffee leaf miner is a small insect pest that affects coffee plants. It is the larval stage of the moth Leucoptera coffeella.",
        #                             symptoms=" The coffee leaf miner larvae tunnel through the leaf tissues, creating serpentine mines. These mines appear as whitish or silverish trails on the leaves. Infested leaves may curl, turn yellow, and drop prematurely. Severe infestations can lead to reduced photosynthesis and decreased yields.",
        #                             treatment="Integrated pest management (IPM) practices are commonly used to control coffee leaf miners. This involves a combination of cultural, biological, and chemical control methods. Cultural practices include maintaining good plant nutrition and hygiene, pruning affected branches, and destroying infested leaves. Biological control involves promoting natural enemies of the leaf miner, such as parasitic wasps. Insecticides can be used if necessary, but their application should follow sustainable practices and be based on expert advice.",
        #                         ),
        #                          Disease(
        #                             name = "Phoma",
        #                             description="Phoma is a fungal disease that affects coffee plants. It is caused by various species of the Phoma genus, such as Phoma exigua var. exigua and Phoma destructiva.",
        #                             symptoms = "Phoma infections primarily affect the fruits (cherries) of coffee plants. Infected cherries develop dark brown to black lesions. The lesions may become sunken and may exude a sticky, gelatinous substance. Severely affected cherries can shrivel and drop prematurely. Phoma can also infect stems and leaves, causing dark brown lesions.",
        #                             treatment = "Managing Phoma involves cultural practices and the use of fungicides. Cultural practices include maintaining proper plant nutrition, removing and destroying infected cherries, and promoting good air circulation. Fungicides can be used to control severe infections, but their application should be based on expert advice to minimize resistance development."
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
