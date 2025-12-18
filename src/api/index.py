from flask import Blueprint

blueprint = Blueprint('blueprint',__name__)

@blueprint.route('/flags/delete', methods=['DELETE'])
def deleteFlag():
    return 'ok'

@blueprint.route('/flags/add', methods=['POST'])
def addFlag():
    return 'ok'

@blueprint.route('/flags/get', methods=['GET'])
def getFlags():
    return 'ok'

@blueprint.route('/passwords/get', methods=['GET'])
def getPasswords():
    return 'ok'

@blueprint.route('/passwords/add', methods=['POST'])
def addPassword():
    return 'ok'

@blueprint.route('/passwords/delete', methods=['DELETE'])
def deletePassword():
    return 'ok'

@blueprint.route('/passwords/update', methods=['PUT'])
def updatePassword():
    return 'ok'

@blueprint.route('/passwords/status', methods=['PUT'])
def updatePasswordStatus():
    return 'ok'

@blueprint.route('/passwords/log', methods=['POST'])
def logPasswordAccess():
    return 'ok'