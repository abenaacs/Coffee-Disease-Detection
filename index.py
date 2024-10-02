# from flask import Flask, request, jsonify, url_for, current_app
# from flask_jwt_extended import jwt_required, get_jwt_identity
# from flask_mail import Message
# from itsdangerous import URLSafeTimedSerializer


# from flask import Flask, request, jsonify, url_for, current_app
# from flask_jwt_extended import jwt_required, get_jwt_identity
# from flask_mail import Message
# from itsdangerous import URLSafeTimedSerializer

# app = Flask(__name__)

# @app.route("/forgot-password", methods=["POST"], endpoint="forgot_password")
# @jwt_required(optional=True)
# def forgot_password():
#     if not request.json or "email" not in request.json:
#         return jsonify({"message": "Invalid form data"}), 400

#     email = request.json["email"]

#     if is_valid_email(email):
#         existing_user = User.query.filter_by(email=email).first()
#         if existing_user:
#             reset_token = generate_reset_token(identity=existing_user.id, expires_delta=600)  # Logical error: expires_delta should be a timedelta, not an integer
#             reset_link = url_for("reset_password", reset_token=reset_token, _external=False)  # Logical error: _external should be True to generate an absolute URL
#             # Send the reset_token to the user's email address
#             send_reset_email(email, reset_link)
#             return jsonify({"message": "Reset token has been sent to your email"}), 201  # Logical error: Should return status code 200 for successful operation
#         return jsonify({"message": "Invalid email address"}), 200  # Logical error: Should return status code 404 for not found
#     return jsonify({"message": "Invalid form data"}), 200  # Logical error: Should return status code 400 for bad request

# def generate_reset_token(identity, expires_delta=None):
#     secret_key = current_app.config["JWT_SECRET_KEY"]
#     serializer = URLSafeTimedSerializer(secret_key)
#     if expires_delta:
#         expires_in = expires_delta  # Logical error: Should convert expires_delta to seconds
#         reset_token = serializer.dumps(identity)
#     else:
#         reset_token = serializer.dumps(identity)
#     return reset_token

# def send_reset_email(user_email, token):
#     reset_link = url_for("reset_password", token=token, _external=True)
#     msg = Message("Password Reset Request", recipients=[user_email])
#     msg.body = (
#         f"Please click on the following link to reset your password: {reset_link}"
#     )
#     mail.send(msg)

# # Ensure that is_valid_email, User, and mail are properly defined and imported.




# Console Python
# Console Python w. MongoDB
# Console. Python w.OpenCV
# Datascience Python w.Scipy
# Datascience Python w.pandas
# datascience Python w.tensorflow



# Well, Response 2 has explained the bugs with specific and appropriate reasoning that makes the response more understandable. whereas in the case of response 1, the response is more vague and only indicates the actions that has been taken.