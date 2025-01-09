from flask import Flask, request, Response, stream_with_context, jsonify
import requests
import os
import logging
import time
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.auto import w3
from functools import wraps
import json
from threading import Lock
import fcntl
from flask_cors import CORS
from werkzeug.utils import secure_filename  # para salvar arquivos com nome seguro

CREDITS_FILE = os.environ.get('CREDITS_FILE', '/data/user_credits.json')
credits_lock = Lock()

# --- MODELS FEATURE ---
MODELS_FILE = os.environ.get('MODELS_FILE', '/data/models.json')
MODELS_FOLDER = os.environ.get('MODELS_FOLDER', '/data/models/')
models_lock = Lock()
models_metadata = {}

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

OLLAMA_URL = "http://localhost:11434"
API_KEY = os.environ.get('API_KEY')

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Maximum signature validity time (7 days in seconds)
SIGNATURE_EXPIRATION = 7 * 24 * 60 * 60

# Guard control
GUARD_ENABLED = True

# Structure to store users and their credits
# {address: {"credits": total_credits, "used": used_credits}}
user_credits = {}

def initialize_credits_file():
    """Ensure credits file exists and is properly initialized"""
    try:
        os.makedirs(os.path.dirname(CREDITS_FILE), exist_ok=True)
        
        if not os.path.exists(CREDITS_FILE):
            with open(CREDITS_FILE, 'w') as f:
                json.dump({}, f)
            logger.info(f"Created new credits file at {CREDITS_FILE}")
        
        os.chmod(CREDITS_FILE, 0o666)
    except Exception as e:
        logger.error(f"Error initializing credits file: {str(e)}")
        raise

# --- MODELS FEATURE ---
def initialize_models_file():
    """Ensure models file exists and is properly initialized"""
    try:
        os.makedirs(os.path.dirname(MODELS_FILE), exist_ok=True)
        os.makedirs(MODELS_FOLDER, exist_ok=True)

        if not os.path.exists(MODELS_FILE):
            with open(MODELS_FILE, 'w') as f:
                json.dump({}, f)
            logger.info(f"Created new models file at {MODELS_FILE}")
        
        # Permissão para escrita
        os.chmod(MODELS_FILE, 0o666)
    except Exception as e:
        logger.error(f"Error initializing models file: {str(e)}")
        raise

def load_credits():
    """Load credits from file"""
    global user_credits
    try:
        with open(CREDITS_FILE, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                user_credits = json.load(f)
                logger.info(f"Loaded credits from file: {user_credits}")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error loading credits: {str(e)}")
        user_credits = {}

# --- MODELS FEATURE ---
def load_models_metadata():
    """Load models metadata from file"""
    global models_metadata
    try:
        with open(MODELS_FILE, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                models_metadata = json.load(f)
                logger.info(f"Loaded models metadata: {models_metadata}")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error loading models metadata: {str(e)}")
        models_metadata = {}

def save_credits():
    """Save credits to file"""
    try:
        with open(CREDITS_FILE, 'r+') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                current_credits = json.load(f)
                current_credits.update(user_credits)
                f.seek(0)
                f.truncate()
                json.dump(current_credits, f)
                logger.info("Credits saved to file")
                user_credits.update(current_credits)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error saving credits: {str(e)}")

# --- MODELS FEATURE ---
def save_models_metadata():
    """Save models metadata to file"""
    try:
        with open(MODELS_FILE, 'r+') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                current_models = json.load(f)
                current_models.update(models_metadata)
                f.seek(0)
                f.truncate()
                json.dump(current_models, f)
                logger.info("Models metadata saved to file")
                models_metadata.update(current_models)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error saving models metadata: {str(e)}")

def get_current_credits(address):
    """Get current credits from file"""
    try:
        with open(CREDITS_FILE, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                credits = json.load(f)
                return credits.get(address)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error reading credits: {str(e)}")
        return None

def validate_timestamp(timestamp_str):
    """Validates if the timestamp is within the allowed period"""
    try:
        timestamp = int(timestamp_str)
        current_time = int(time.time())
        if current_time - timestamp > SIGNATURE_EXPIRATION:
            return False, "Expired timestamp"
        if timestamp > current_time:
            return False, "Future timestamp"
        return True, None
    except ValueError:
        return False, "Invalid timestamp"

def verify_signature(signature, timestamp):
    """Verifies the web3 signature and returns the signing address"""
    try:
        message = timestamp
        message_hash = encode_defunct(text=str(message))
        
        if signature.startswith('0x'):
            signature = signature[2:]
            
        signature = '0x' + signature
        
        address = w3.eth.account.recover_message(message_hash, signature=signature)
        
        logger.info(f"Message used for verification: {message}")
        logger.info(f"Recovered address: {address}")
        
        return True, address
    except Exception as e:
        logger.error(f"Error verifying signature: {str(e)}")
        return False, None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_key = request.headers.get('Authorization')
        if admin_key and admin_key == f"Bearer {API_KEY}":
            return f(*args, **kwargs)

        signature_header = request.headers.get('X-Signature')
        if not signature_header:
            return jsonify({"error": "Signature not provided"}), 401

        try:
            signature, timestamp = signature_header.split('-')
            
            is_valid, error = validate_timestamp(timestamp)
            if not is_valid:
                return jsonify({"error": error}), 401

            logger.info(f"Validating signature: {signature}")
            logger.info(f"With timestamp: {timestamp}")

            is_valid, address = verify_signature(signature, timestamp)
            if not is_valid:
                return jsonify({"error": "Invalid signature"}), 401

            # Only check whitelist if guard is enabled
            if GUARD_ENABLED:
                if address not in user_credits:
                    logger.info(f"Users with credits: {user_credits.keys()}")
                    return jsonify({
                        "error": "Unauthorized address",
                        "address": address,
                        "message_used": timestamp
                    }), 401

            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return jsonify({"error": "Authentication error"}), 401

    return decorated

@app.route('/manage/users', methods=['POST'])
def manage_users():
    admin_key = request.headers.get('Authorization')
    if not admin_key or admin_key != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    action = data.get('action')
    address = data.get('address')
    credits = data.get('credits', 0)

    if not action or not address:
        return jsonify({"error": "Invalid parameters"}), 400

    response = None
    
    if action == 'add':
        user_credits[address] = {"credits": credits, "used": 0}
        response = jsonify({
            "message": f"Address {address} added",
            "credits": credits
        })
    elif action == 'remove':
        if address in user_credits:
            del user_credits[address]
        response = jsonify({"message": f"Address {address} removed"})
    elif action == 'add_credits':
        if address not in user_credits:
            return jsonify({"error": "User not found"}), 404
        user_credits[address]["credits"] += credits
        response = jsonify({
            "message": f"Credits added for {address}",
            "total_credits": user_credits[address]["credits"]
        })
    elif action == 'reset_usage':
        if address not in user_credits:
            return jsonify({"error": "User not found"}), 404
        user_credits[address]["used"] = 0
        response = jsonify({
            "message": f"Usage reset for {address}",
            "credits_remaining": user_credits[address]["credits"]
        })
    else:
        return jsonify({"error": "Invalid action"}), 400
    
    save_credits()
    return response

@app.route('/admin/guard', methods=['POST'])
def manage_guard():
    """Admin endpoint to enable/disable guard"""
    global GUARD_ENABLED
    
    admin_key = request.headers.get('Authorization')
    if not admin_key or admin_key != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    enabled = data.get('enabled')
    
    if enabled is None:
        return jsonify({"error": "Missing 'enabled' parameter"}), 400
        
    GUARD_ENABLED = bool(enabled)
    
    return jsonify({
        "message": f"Guard {'enabled' if GUARD_ENABLED else 'disabled'}",
        "status": GUARD_ENABLED
    })

def get_current_user():
    """Gets the address of the current request's user"""
    signature_header = request.headers.get('X-Signature')
    if not signature_header:
        return None
    
    try:
        signature, timestamp = signature_header.split('-')
        is_valid, address = verify_signature(signature, timestamp)
        return address if is_valid else None
    except:
        return None

def check_credits(address):
    """Checks if the user has available credits"""
    user = get_current_credits(address)
    if not user:
        return False, "Unauthorized user"
    
    if user["used"] >= user["credits"]:
        return False, "Credits exhausted"
    
    return True, None

def increment_usage(address):
    """Increments the user's usage counter"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with open(CREDITS_FILE, 'r+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    credits = json.load(f)
                    
                    if address not in credits:
                        logger.error(f"User {address} not found in credits file")
                        return False
                        
                    if credits[address]["used"] >= credits[address]["credits"]:
                        logger.error(f"No credits left for {address}")
                        return False
                        
                    credits[address]["used"] += 1
                    
                    f.seek(0)
                    f.truncate()
                    json.dump(credits, f)
                    
                    logger.info(f"Incremented usage for {address}. Used: {credits[address]['used']}")
                    return True
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Error incrementing usage (attempt {attempt+1}/{max_retries}): {str(e)}")
            if attempt == max_retries - 1:
                return False
            time.sleep(0.1)
    return False

@app.route('/credits', methods=['GET'])
@require_auth
def get_credits():
    signature_header = request.headers.get('X-Signature')
    if not signature_header:
        return jsonify({"error": "Signature not provided"}), 401

    try:
        signature, timestamp = signature_header.split('-')
        is_valid, address = verify_signature(signature, timestamp)
        if not is_valid:
            return jsonify({"error": "Invalid signature"}), 401

        user = get_current_credits(address)
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "address": address,
            "total_credits": user["credits"],
            "used_credits": user["used"],
            "remaining_credits": user["credits"] - user["used"]
        })

    except Exception as e:
        logger.error(f"Error checking credits: {str(e)}")
        return jsonify({"error": "Error checking credits"}), 500

@app.route('/admin/user_credits/<address>', methods=['GET'])
def admin_get_user_credits(address):
    """Admin endpoint to check any user's credits"""
    admin_key = request.headers.get('Authorization')
    if not admin_key or admin_key != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized"}), 401

    user = get_current_credits(address)
    if not user:
        return jsonify({
            "error": "User not found",
            "address": address
        }), 404

    return jsonify({
        "address": address,
        "total_credits": user["credits"],
        "used_credits": user["used"],
        "remaining_credits": user["credits"] - user["used"],
        "usage_percentage": (user["used"] / user["credits"] * 100) if user["credits"] > 0 else 0
    })

# --- MODELS FEATURE ---
@app.route('/models', methods=['POST'])
@require_auth
def upload_model():
    """
    Endpoint para upload de um novo modelo.
    Espera um form-data (multipart) com, por exemplo:
      - model_file: (arquivo .gguf ou similar)
      - model_name: string
      - visibility: 'public' ou 'whitelisted'
      - allowed_addresses: lista de endereços (opcional)
    """
    admin_key = request.headers.get('Authorization')
    address = None

    # Identifica o address (caso não seja admin)
    if admin_key and admin_key == f"Bearer {API_KEY}":
        # Admin pode efetuar upload em nome dele mesmo ou “em nome do sistema”
        address = "ADMIN"
    else:
        address = get_current_user()
        if not address:
            return jsonify({"error": "User not identified"}), 401

    # Verifica se veio o arquivo
    if 'model_file' not in request.files:
        return jsonify({"error": "No model_file provided"}), 400

    file = request.files['model_file']

    # Metadados
    model_name = request.form.get('model_name', '').strip()
    visibility = request.form.get('visibility', 'public').lower()
    allowed_addresses_str = request.form.get('allowed_addresses', '')

    # Valida campos
    if not model_name:
        return jsonify({"error": "model_name is required"}), 400

    if visibility not in ['public', 'whitelisted']:
        return jsonify({"error": "visibility must be public or whitelisted"}), 400

    # Caso o usuário queira whitelisted mas não passou allowed_addresses, vira lista vazia
    allowed_addresses = []
    if allowed_addresses_str:
        try:
            # Exemplo: "0xabc, 0xdef, 0xghi"
            allowed_addresses = [x.strip() for x in allowed_addresses_str.split(',')]
        except:
            allowed_addresses = []

    # Garante nome único (simples, mas você pode querer algo mais robusto)
    if model_name in models_metadata:
        return jsonify({"error": f"Model '{model_name}' already exists"}), 400

    filename = secure_filename(file.filename)
    extension = os.path.splitext(filename)[1]  # e.g. .gguf
    if not extension:
        extension = ".gguf"  # Default

    save_path = os.path.join(MODELS_FOLDER, f"{model_name}{extension}")

    try:
        file.save(save_path)
    except Exception as e:
        logger.error(f"Error saving model file: {str(e)}")
        return jsonify({"error": "Failed to save model file"}), 500

    # Atualiza metadados
    with models_lock:
        models_metadata[model_name] = {
            "owner": address,
            "visibility": visibility,
            "allowed_addresses": allowed_addresses,
            "file_path": save_path
        }
        save_models_metadata()

    return jsonify({
        "message": f"Model '{model_name}' uploaded successfully",
        "model_name": model_name,
        "owner": address,
        "visibility": visibility,
        "allowed_addresses": allowed_addresses
    })

# --- MODELS FEATURE ---
@app.route('/models', methods=['GET'])
@require_auth
def list_models():
    """
    Lists available models:
      - If admin, lists all models
      - If a regular user, lists:
          -> public models
          -> models where the user is the owner
          -> whitelisted models where the user is in allowed_addresses
    """
    admin_key = request.headers.get('Authorization')
    is_admin = (admin_key and admin_key == f"Bearer {API_KEY}")
    current_address = get_current_user() if not is_admin else "ADMIN"

    results = []
    with models_lock:
        for model_name, meta in models_metadata.items():
            # If admin, list all models
            if is_admin:
                results.append({
                    "model_name": model_name,
                    **meta
                })
            else:
                # If the model is public
                if meta["visibility"] == "public":
                    results.append({"model_name": model_name, **meta})
                # Or if the user is the owner of the model
                elif meta["owner"] == current_address:
                    results.append({"model_name": model_name, **meta})
                # Or if it is whitelisted and the current_address is in the allowed list
                elif meta["visibility"] == "whitelisted" and current_address in meta["allowed_addresses"]:
                    results.append({"model_name": model_name, **meta})

    return jsonify(results)

# --- MODELS FEATURE ---
@app.route('/models/<model_name>', methods=['DELETE'])
@require_auth
def delete_model(model_name):
    """
    Deletes a model if:
      - The user is admin, or
      - The user is the owner of the model
    Removes the model file from disk and updates the metadata.
    """
    admin_key = request.headers.get('Authorization')
    is_admin = (admin_key and admin_key == f"Bearer {API_KEY}")
    current_address = get_current_user() if not is_admin else "ADMIN"

    with models_lock:
        if model_name not in models_metadata:
            return jsonify({"error": "Model not found"}), 404

        meta = models_metadata[model_name]
        owner = meta["owner"]

        # Only delete if admin or owner
        if not is_admin and current_address != owner:
            return jsonify({"error": "Not authorized to delete this model"}), 403

        file_path = meta["file_path"]
        # Remove the file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Error deleting model file: {str(e)}")

        del models_metadata[model_name]
        save_models_metadata()

    return jsonify({"message": f"Model '{model_name}' deleted successfully"})

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@require_auth
def proxy(path):
    admin_key = request.headers.get('Authorization')
    if not admin_key or admin_key != f"Bearer {API_KEY}":
        address = get_current_user()
        if not address:
            return jsonify({"error": "User not identified"}), 401
        
        # Log the address making the request
        logger.info(f"Request from address: {address}")
        
        # Only check credits if guard is enabled
        if GUARD_ENABLED:
            has_credits, error = check_credits(address)
            if not has_credits:
                return jsonify({
                    "error": error,
                    "address": address,
                    "credits_info": get_current_credits(address)
                }), 403

    url = f"{OLLAMA_URL}/{path}"
    
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            stream=True
        )

        # Only increment usage if guard is enabled and not admin
        if resp.status_code == 200 and GUARD_ENABLED and not (admin_key and admin_key == f"Bearer {API_KEY}"):
            if not increment_usage(address):
                return jsonify({"error": "Failed to increment usage"}), 500

        return Response(
            stream_with_context(resp.iter_content(chunk_size=1024)),
            content_type=resp.headers.get('Content-Type'),
            status=resp.status_code
        )
    except Exception as e:
        logger.error(f"Error in LLM call: {str(e)}")
        return jsonify({"error": "Error processing LLM request"}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})

def init_app():
    """Initialize the application"""
    logger.info(f"Initializing application with credits file: {CREDITS_FILE}")
    initialize_credits_file()
    load_credits()
    
    logger.info(f"Initializing application with models file: {MODELS_FILE}")
    initialize_models_file()
    load_models_metadata()

    logger.info("Application initialized")

if __name__ == '__main__':
    init_app()
    app.run(host='0.0.0.0', port=8080)
else:
    init_app()
