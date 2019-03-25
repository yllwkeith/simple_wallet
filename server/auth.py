from flask import make_response, jsonify, g as flask_storage
from flask_httpauth import HTTPBasicAuth

from werkzeug.security import check_password_hash

from db import User

auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        flask_storage.current_user = user
        return True
    return False


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)
