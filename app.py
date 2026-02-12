from flask import Flask, request, jsonify, session, send_from_directory
from flask_session import Session
import webauthn
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import secrets
import base64
import json
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

Session(app)

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        origin = request.headers.get('Origin')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        return response

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# In-memory storage
users_db = {}
credentials_db = {}

# Configuration
RP_ID = "localhost"
RP_NAME = "Your Website"
ORIGIN = "http://localhost:8081"

# Helper functions
def base64url_to_bytes(data):
    padding = '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def bytes_to_base64url(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

# Serve HTML
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/check-support', methods=['GET'])
def check_support():
    return jsonify({
        'supported': True,
        'message': 'WebAuthn is supported'
    })

@app.route('/api/register-challenge', methods=['POST'])
def register_challenge():
    try:
        data = request.json
        email = data.get('email')
        username = data.get('username', email)
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if email in users_db:
            return jsonify({'error': 'User already exists'}), 400
        
        user_id = secrets.token_bytes(32)
        
        session['pending_user'] = {
            'email': email,
            'username': username,
            'user_id': bytes_to_base64url(user_id)
        }
        
        registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=email,
            user_display_name=username,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256
            ],
            timeout=60000
        )
        
        session['registration_challenge'] = bytes_to_base64url(registration_options.challenge)
        options_json = options_to_json(registration_options)
        
        return jsonify(json.loads(options_json))
        
    except Exception as e:
        print(f"Registration challenge error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/register-verify', methods=['POST'])
def register_verify():
    try:
        data = request.json
        pending_user = session.get('pending_user')
        expected_challenge = session.get('registration_challenge')
        
        if not pending_user or not expected_challenge:
            return jsonify({'error': 'No pending registration'}), 400
        
        credential = RegistrationCredential(
            id=data['id'],
            raw_id=base64url_to_bytes(data['rawId']),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(data['response']['clientDataJSON']),
                attestation_object=base64url_to_bytes(data['response']['attestationObject']),
            ),
            authenticator_attachment=data.get('authenticatorAttachment'),
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(expected_challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )
        
        email = pending_user['email']
        user_id = pending_user['user_id']
        
        users_db[email] = {
            'user_id': user_id,
            'username': pending_user['username'],
            'email': email
        }
        
        credentials_db[email] = {
            'credential_id': bytes_to_base64url(verification.credential_id),
            'credential_public_key': bytes_to_base64url(verification.credential_public_key),
            'sign_count': verification.sign_count,
            'credential_type': verification.credential_type,
            'credential_device_type': verification.credential_device_type,
            'credential_backed_up': verification.credential_backed_up
        }
        
        session.pop('pending_user', None)
        session.pop('registration_challenge', None)
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user_id': user_id
        })
        
    except Exception as e:
        print(f"Registration verify error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login-challenge', methods=['POST'])
def login_challenge():
    try:
        data = request.json
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if email not in users_db:
            return jsonify({'error': 'User not found'}), 404
        
        user_credential = credentials_db.get(email)
        if not user_credential:
            return jsonify({'error': 'No credentials found'}), 404
        
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(user_credential['credential_id'])
            )
        ]
        
        authentication_options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=60000
        )
        
        session['authentication_challenge'] = bytes_to_base64url(authentication_options.challenge)
        session['login_email'] = email
        
        options_json = options_to_json(authentication_options)
        
        return jsonify(json.loads(options_json))
        
    except Exception as e:
        print(f"Login challenge error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login-verify', methods=['POST'])
def login_verify():
    try:
        data = request.json
        expected_challenge = session.get('authentication_challenge')
        email = session.get('login_email')
        
        if not expected_challenge or not email:
            return jsonify({'error': 'No pending authentication'}), 400
        
        user_credential = credentials_db.get(email)
        if not user_credential:
            return jsonify({'error': 'Credential not found'}), 404
        
        credential = AuthenticationCredential(
            id=data['id'],
            raw_id=base64url_to_bytes(data['rawId']),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(data['response']['clientDataJSON']),
                authenticator_data=base64url_to_bytes(data['response']['authenticatorData']),
                signature=base64url_to_bytes(data['response']['signature']),
                user_handle=base64url_to_bytes(data['response']['userHandle']) if data['response'].get('userHandle') else None,
            ),
            authenticator_attachment=data.get('authenticatorAttachment'),
        )
        
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(expected_challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64url_to_bytes(user_credential['credential_public_key']),
            credential_current_sign_count=user_credential['sign_count']
        )
        
        credentials_db[email]['sign_count'] = verification.new_sign_count
        
        session['logged_in'] = True
        session['user_email'] = email
        session.pop('authentication_challenge', None)
        session.pop('login_email', None)
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': users_db[email]
        })
        
    except Exception as e:
        print(f"Login verify error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/api/user', methods=['GET'])
def get_user():
    if session.get('logged_in'):
        email = session.get('user_email')
        return jsonify(users_db.get(email))
    return jsonify({'error': 'Not logged in'}), 401

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8081)