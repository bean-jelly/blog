from . import api
from flask import jsonify
from ..exceptions import ValidationError

def bad_request(message):
    response = jsonify({'error': 'bad request', 'message': message})
    response.status_code = 400
    return response

def unauthorized(message):
    respones = jsonify({'error':'unauthorized', 'message':message})
    respones.status_code = 401
    return respones

def forbidden(message):
    respones = jsonify({'error':'forbidden', 'message':message})
    respones.status_code = 403
    return respones

@api.errorhandler(ValidationError)
def validation_error(e):
    return bad_request(e.args[0])

