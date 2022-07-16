from json import loads
import os
from glob import glob
from io import BytesIO
from zipfile import ZipFile
from marshmallow import ValidationError

from flask import jsonify, request, send_file
from flask_jwt_extended import (create_access_token, current_user,
                                jwt_required)
from support_classes.certs import KeyCsrGenerator, StoreCreater
from support_classes.enc_dec import EncDec
from support_classes.requests_modul import DataSender
from support_classes.container_creater import create_certs_container, _decode_key
from support_classes.schema import schema_register_user, schema_login_user, \
    schema_create_cerificate, schema_create_container
from app import app, db, jwt
from app.models import Certs, Tasks, Users
from support_classes.secman_int import SecManInt

sec_int = SecManInt(app.logger)

@app.route('/certificate', methods=['POST'])
@jwt_required()
def add_message():
    password_secret = sec_int.getSecret()
    app.logger.info('Got new cert creation request')
    json_data = request.json
    try:
        content = schema_create_cerificate.load(json_data)
    except ValidationError as error:
        return jsonify({"success": False, "error": error.messages}), 400
    if content["subject"]["subject_exists"]:
        req = KeyCsrGenerator(
            app.logger,
            C=content["subject"]["country"],
            O=content["subject"]["organization"],
            ST=content["subject"]["state_of_province"],
            L=content["subject"]["location"],
            OU=content["subject"]["organization_unit"],
            CN=content["commonName"],
            auth=content["cert_auth"]
        )
    if content["dnses_exists"] is True:
        dnses = []
        for values in content["dnses"].values():
            dnses.append(values)
        req.dnses = dnses
    csr, key = req.generateCsr()
    ds = DataSender(
        app.logger,
        tok='some_token',
        ci=content['ci'],
        csr=csr, email=content['email_specified'],
        cert_type=content['cert_type'],
        cert_du=content['time'],
        val=content['email_val'], ca_type=content['ca_type'],
        url=URL
    )
    task_id = ds.csrSender()
    if task_id:
        # try:
        tasks = Tasks(
            status=False,
            task_id=task_id,
        )
        db.session.add(tasks)
        db.session.commit()
        if 'key_storage' not in content or content['key_storage'] is True:
            ed = EncDec(app.logger, password_secret, key.decode('UTF-8'))
            key2 = ed.encryptCell()
            certs = Certs(
                name=content['cert_name'],
                csr=csr, key=key2,
                pem='', auth_attr=content['cert_auth'],
                email_specified=content['email_specified'],
                user_id=current_user.id,
                tasks_id=tasks.id,
                key_storage=True
            )
            db.session.add(certs)
            db.session.commit()
            return jsonify({"success": True, "task_id": task_id})
        else:
            certs = Certs(
                name=content['cert_name'],
                csr=csr, key='',
                pem='', auth_attr=content['cert_auth'],
                email_specified=content['email_specified'],
                user_id=current_user.id,
                tasks_id=tasks.id,
                key_storage=True
            )
            db.session.add(certs)
            db.session.commit()
            msg = {"success": True, "task_id": task_id, "key": key.decode("UTF-8")}
            print(msg)
            return jsonify(msg)


@app.route('/certificate/<int:cert_id>', methods=['GET'])
@jwt_required()
def get_cert(cert_id):
    password_secret = sec_int.getSecret()
    try:
        user_certificates = db.session.query(Certs, Tasks).join(Tasks) \
            .filter(Certs.user_id == current_user.id) \
            .filter(Tasks.task_id == cert_id).all()
        if not user_certificates:
            return jsonify({"success": False, "msg": "You don't have access to the certificate"}), 403
        for cert, task in user_certificates:
            if cert.pem == "":
                return jsonify({"success": False, "msg": "You certificate is not ready"})
            if cert.key_storage == True:
                decode_key = _decode_key(str(cert.key), password_secret)
                msg = {"success": True, "published_certificate": cert.pem, "private_key": decode_key}
                return jsonify(msg)
            else:
                msg = {"success": True, "published_certificate": cert.pem}
                return jsonify(msg)
    except Exception as e:
        app.logger.error(f"Can not get certificate. Cause: {str(e)}")


@app.route('/get_stores/<int:cert_id>', methods=['GET'])
@jwt_required()
def get_stores(cert_id):
    json_data = request.json
    try:
        content = schema_create_container.load(json_data)
    except ValidationError as error:
        return jsonify(error.messages), 400
    app.logger.info(f'Got keystores request for task id {cert_id}')
    Tasks.query.filter_by(task_id=int(cert_id)).first_or_404()
    result = db.session.query(Certs, Tasks).join(Tasks) \
        .filter(Tasks.task_id == int(cert_id)) \
        .filter(Certs.user_id == current_user.id).all()
    if not result:
        return jsonify({"success": False,"msg": "You don't have access to the certificate"}), 403
    for certs, task in result:
        if not certs.pem or not certs.key:
            return jsonify({"success": False, "msg": "You certificate not ready, and stores too"})
        bytes_files: dict = create_certs_container(cert_id, content['password'], content['jks'], content['p12'])
        if bytes_files:
            stream = BytesIO()
            with ZipFile(stream, 'w') as zf:
                for names, file in bytes_files.items():
                    zf.writestr(names, data=file.getvalue())
            stream.seek(0)
            try:
                app.logger.info(f'"msg": Files for task id {cert_id} sent')
                return send_file(stream, as_attachment=True, attachment_filename='archive.zip')
            except Exception as e:
                app.logger.error(str(e))


@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    if current_user.role != 'admin':
        return jsonify({"msg": "Аction not available, your role user"})
    json_data = request.json
    try:
        content = schema_register_user.load(json_data)
    except ValidationError as error:
        return jsonify(error.messages), 400
    check_user = Users.query.filter_by(username=content['username']).first()
    if check_user is not None:
        return jsonify({"msg": "User already exists"})
    user = Users(
        username=content["username"],
        password=content["password"],
        name=content["name"],
        email=content['email'],
        ops_group_id=content["ops_group_id"],
        role=content["role"])
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "You have successful registered "})


@app.route("/login", methods=["POST"])
def login():
    json_data = request.json
    try:
        content = schema_login_user.load(json_data)
    except ValidationError as error:
        return jsonify(error.messages), 400
    user = Users.query.filter_by(username=content['username']).one_or_none()
    if not user or not user.verify_password(pwd=str(content['password'])):
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=user)
    return jsonify({"access_token": access_token})

if ROUTE_REGISTER_ADMIN:
    @app.route('/register_admin', methods=['POST'])
    def register_admin():
        content = request.json
        user = Users(
            username=content["username"],
            password=content["password"],
            name=content["name"],
            email=content['email'],
            ops_group_id=content["ops_group_id"],
            role=content["role"])
        db.session.add(user)
        db.session.commit()
        return jsonify({"msg": "You successful register"})


@app.route('/user_info', methods=['GET'])
@jwt_required()
def user_info():
    return jsonify({"id": current_user.id,
                    "role": current_user.role,
                    "username": current_user.username})


@jwt.user_identity_loader
def user_identity_lookup(users):
    return users.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Users.query.filter_by(id=identity).one_or_none()
