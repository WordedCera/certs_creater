from marshmallow import Schema, fields
from marshmallow.validate import Length, Range, OneOf


class RegisterUser(Schema):
    username = fields.Str(required=True, validate=Length(min=1, max=50))
    password = fields.Str(required=True, validate=Length(min=6, max=20))
    name = fields.Str(required=True, validate=Length(min=3, max=30))
    email = fields.Email(required=True)
    ops_group_id = fields.Integer(required=True, validate=Range(min=1, max=2))
    role = fields.Str(required=True, validate=OneOf(['user', 'admin']))


class LoginUser(Schema):
    username = fields.Str(required=True, validate=Length(min=1, max=50))
    password = fields.Str(required=True, validate=Length(min=6, max=20))


class SubjectCertificate(Schema):
    subject_exists = fields.Boolean(required=True)
    country = fields.Str(required=True, validate=Length(min=2, max=4))
    organization = fields.Str(required=True, validate=Length(min=2, max=15))
    state_of_province = fields.Str(required=True, validate=Length(min=2, max=15))
    location = fields.Str(required=True, validate=Length(min=2, max=15))
    organization_unit = fields.Str(required=True, validate=Length(min=2, max=10))


class CreateCertificate(Schema):
    cert_name = fields.Str(required=True, validate=Length(min=3, max=30))
    commonName = fields.Str(required=True, validate=Length(min=3, max=30))
    cert_auth = fields.Str(required=True, validate=OneOf(
        ['clientAuth', 'serverAuth', 'clientAuth, serverAuth']))
    ci = fields.Str(required=True, validate=Length(min=10, max=15))
    time = fields.Str(required=True, validate=OneOf(
        ['3y', '1y']))
    ca_type = fields.Str(required=True, validate=OneOf(
        ['some_segment', 'some_segment2', 'some_segment3', 'some_segment4', 'some_segment5']))
    cert_type = fields.Str(required=True, validate=OneOf(
        ["server", 'client', 'universal']))
    email_val = fields.Str(required=True, validate=OneOf(
        ['t', 'f']))
    subject = fields.Nested(SubjectCertificate)
    dnses_exists = fields.Boolean(required=True)
    dnses = fields.Dict(required=False, keys=fields.Str(), values=fields.Str())
    email_specified = fields.Email(required=True)
    key_storage = fields.Boolean(required=False)


class CreateContainer(Schema):
    jks = fields.Boolean(required=True)
    p12 = fields.Boolean(required=True)
    password = fields.Str(required=True, validate=Length(min=8, max=30))


schema_register_user = RegisterUser()
schema_login_user = LoginUser()
schema_create_cerificate = CreateCertificate()
schema_create_container = CreateContainer() 
