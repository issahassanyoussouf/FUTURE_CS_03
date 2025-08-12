# app.py
import os
import base64
import json
import io
import logging
from datetime import datetime
from flask import Flask, request, send_file, render_template, jsonify, abort
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Config ---
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
META_FOLDER = os.path.join(os.getcwd(), 'keys')       # métadonnées par fichier
DECRYPTED_FOLDER = os.path.join(os.getcwd(), 'decrypted')
ALLOWED_EXT = None  # None = autoriser tout ; tu peux restreindre par extension si souhaité

for d in (UPLOAD_FOLDER, META_FOLDER, DECRYPTED_FOLDER):
    os.makedirs(d, exist_ok=True)

# Chargement de la clé maître (base64 dans variable d'environnement)
MASTER_KEY_B64 = os.environ.get('FILE_VAULT_MASTER_KEY')
ADMIN_TOKEN = os.environ.get('FILE_VAULT_ADMIN_TOKEN')

if not MASTER_KEY_B64:
    print("⚠️ WARNING: FILE_VAULT_MASTER_KEY not set. Using ephemeral key (NOT for production).")
    MASTER_KEY = get_random_bytes(32)
else:
    try:
        MASTER_KEY = base64.b64decode(MASTER_KEY_B64)
        if len(MASTER_KEY) != 32:
            raise ValueError("Master key must decode to 32 bytes (AES-256).")
    except Exception as e:
        print("Invalid FILE_VAULT_MASTER_KEY:", e)
        raise

if not ADMIN_TOKEN:
    print("⚠️ WARNING: FILE_VAULT_ADMIN_TOKEN not set. Set a token in env for protection.")

# Logging
logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s %(message)s')

app = Flask(__name__)


def require_token():
    """Vérifie le token envoyé (header X-Auth-Token ou champ form token)."""
    if not ADMIN_TOKEN:
        return False
    token = request.headers.get('X-Auth-Token') or request.form.get('token')
    return token == ADMIN_TOKEN


def log_action(action, filename):
    ip = request.remote_addr or "local"
    logging.info(f"{action} file={filename} ip={ip}")


# --- Crypto helpers (AES-GCM) ---
# Format stocké : nonce (12 bytes) | tag (16 bytes) | ciphertext
def encrypt_bytes(plaintext: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def decrypt_bytes(blob: bytes) -> bytes:
    if len(blob) < (12 + 16):
        raise ValueError("Blob too small")
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html', token_required=bool(ADMIN_TOKEN))


@app.route('/upload', methods=['POST'])
def upload():
    if ADMIN_TOKEN and not require_token():
        abort(401, description="Missing or invalid X-Auth-Token")

    if 'file' not in request.files:
        return jsonify({'error': 'no file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'empty filename'}), 400

    # sanitize filename
    original_name = secure_filename(file.filename)
    if original_name == '':
        return jsonify({'error': 'invalid filename after sanitization'}), 400

    data = file.read()
    encrypted_blob = encrypt_bytes(data)

    # saved filename (add .enc to avoid confusion)
    enc_name = original_name + '.enc'
    enc_path = os.path.join(UPLOAD_FOLDER, enc_name)
    with open(enc_path, 'wb') as f:
        f.write(encrypted_blob)

    # metadata
    meta = {
        'original_name': original_name,
        'stored_name': enc_name,
        'uploaded_at': datetime.utcnow().isoformat() + 'Z',
        'uploader_ip': request.remote_addr
    }
    meta_path = os.path.join(META_FOLDER, enc_name + '.meta.json')
    with open(meta_path, 'w', encoding='utf-8') as mf:
        json.dump(meta, mf, ensure_ascii=False, indent=2)

    log_action('UPLOAD', enc_name)
    return jsonify({'status': 'ok', 'stored_name': enc_name, 'original_name': original_name})


@app.route('/files', methods=['GET'])
def list_files():
    if ADMIN_TOKEN and not require_token():
        abort(401, description="Missing or invalid X-Auth-Token")

    files = []
    for fname in os.listdir(UPLOAD_FOLDER):
        if not fname.endswith('.enc'):
            continue
        meta_file = os.path.join(META_FOLDER, fname + '.meta.json')
        meta = {}
        if os.path.exists(meta_file):
            try:
                with open(meta_file, 'r', encoding='utf-8') as mf:
                    meta = json.load(mf)
            except Exception:
                pass
        files.append({'stored_name': fname, 'meta': meta})
    return jsonify(files)


@app.route('/download/<path:stored_name>', methods=['GET'])
def download(stored_name):
    if ADMIN_TOKEN and not require_token():
        abort(401, description="Missing or invalid X-Auth-Token")

    safe_name = secure_filename(stored_name)
    if not safe_name.endswith('.enc'):
        safe_name = safe_name + '.enc'

    enc_path = os.path.join(UPLOAD_FOLDER, safe_name)
    if not os.path.exists(enc_path):
        return jsonify({'error': 'file not found'}), 404

    # load and decrypt
    with open(enc_path, 'rb') as ef:
        blob = ef.read()
    try:
        plaintext = decrypt_bytes(blob)
    except Exception as e:
        return jsonify({'error': 'decryption failed', 'msg': str(e)}), 500

    # obtain original filename from metadata if present
    meta_path = os.path.join(META_FOLDER, safe_name + '.meta.json')
    original_name = None
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r', encoding='utf-8') as mf:
                meta = json.load(mf)
                original_name = meta.get('original_name')
        except Exception:
            original_name = None

    if not original_name:
        # fallback
        original_name = safe_name[:-4]

    # stream back without writing to disk
    bio = io.BytesIO(plaintext)
    bio.seek(0)
    log_action('DOWNLOAD', safe_name)
    # Flask 2.0+: use download_name param, older versions use attachment_filename
    return send_file(bio, as_attachment=True, download_name=original_name)


@app.route('/delete/<path:stored_name>', methods=['DELETE'])
def delete(stored_name):
    if ADMIN_TOKEN and not require_token():
        abort(401, description="Missing or invalid X-Auth-Token")

    safe_name = secure_filename(stored_name)
    if not safe_name.endswith('.enc'):
        safe_name = safe_name + '.enc'

    enc_path = os.path.join(UPLOAD_FOLDER, safe_name)
    meta_path = os.path.join(META_FOLDER, safe_name + '.meta.json')

    if os.path.exists(enc_path):
        os.remove(enc_path)
    if os.path.exists(meta_path):
        os.remove(meta_path)

    log_action('DELETE', safe_name)
    return jsonify({'status': 'deleted', 'file': safe_name})


if __name__ == '__main__':
    # Dev server (not pour production) :
    app.run(host='0.0.0.0', port=5000, debug=True)
