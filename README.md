# Secure File Sharing System (Flask + AES-GCM)

A secure file sharing system built with:

*  AES-GCM encryption (confidentiality + integrity)
*  Admin authentication via HTTP token header
*  Flask web interface (upload/download/delete)
*  Local storage of encrypted files + metadata
*  Fully compatible with Windows (Python + PowerShell + waitress)

Perfect for a proof-of-concept, internship project, or security demonstration.

---

## Features

* Upload files via web interface or API
* AES-256 GCM encryption (random nonce per file)
* Real-time decryption on download (no temp files stored)
* All endpoints protected via admin token (X-Auth-Token)
* Metadata stored per file: original name, IP, timestamp
* Action logging (uploads/downloads/deletions)

---

## 📁 Project Structure

```
secure_file_system/
├── app.py                  # Flask application
├── run.ps1                 # PowerShell script to run the server with Waitress
├── requirements.txt        # Python dependencies
├── .gitignore              # Ignore sensitive files
├── templates/
│   └── index.html          # Minimal web interface
├── uploads/                # Encrypted files (.enc)
├── decrypted/              # (Not used in production)
├── keys/                   # Metadata (.json) per file
└── access.log              # Logs of all actions
```

---

## Setup Instructions (Windows + PowerShell)

1. Install Python 3.9+ (if needed):

```powershell
winget install --id Python.Python.3 -e
```

2. Clone the repository:

```powershell
git clone https://github.com/your-username/secure_file_system.git
cd secure_file_system
```

3. Create virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

4. Install dependencies:

```powershell
pip install -r requirements.txt
```

---

## Environment Variables (Master Key + Admin Token)

1. Generate a 32-byte base64 master key (AES-256):

```powershell
python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
```

2. Generate an admin token:

```powershell
python -c "import secrets;print(secrets.token_urlsafe(32))"
```

3. Set environment variables (persistently):

```powershell
setx FILE_VAULT_MASTER_KEY "<your_base64_key>"
setx FILE_VAULT_ADMIN_TOKEN "<your_token>"
```

(Optional: for current PowerShell session only):

```powershell
$env:FILE_VAULT_MASTER_KEY = "<your_base64_key>"
$env:FILE_VAULT_ADMIN_TOKEN = "<your_token>"
```

---

## Running the App

Dev mode:

```powershell
python app.py
```

Production (recommended on Windows):

```powershell
.\run.ps1
```

→ Access it at: [http://localhost:8080](http://localhost:8080)

---

## Web Interface

Navigate to: [http://localhost:8080](http://localhost:8080)
<img width="1366" height="694" alt="Capture d’écran (2856)" src="https://github.com/user-attachments/assets/11537f34-2feb-4bfe-a025-0d8a5da90c3a" />

Features:

* Upload file with simple HTML form
* Optional token input
* JSON output for response

---

## API Endpoints

All routes require the following header:

X-Auth-Token: \<your\_admin\_token>

| Method | Endpoint                  | Description             |
| ------ | ------------------------- | ----------------------- |
| POST   | /upload                   | Upload + encrypt file   |
| GET    | /files                    | List all stored files   |
| GET    | /download/\<stored\_name> | Decrypt + download file |
| DELETE | /delete/\<stored\_name>   | Delete file + metadata  |

Examples:

Upload:

```bash
curl -X POST -H "X-Auth-Token: your_token" -F "file=@myfile.txt" http://localhost:8080/upload
```
<img width="1366" height="727" alt="Capture d’écran (2868)" src="https://github.com/user-attachments/assets/1ac684fa-ac3b-4c1a-8d0d-629d6d19eefb" />

Download:

```bash
curl -H "X-Auth-Token: your_token" http://localhost:8080/download/myfile.txt.enc -o decrypted.txt
```
<img width="1366" height="727" alt="Capture d’écran (2873)" src="https://github.com/user-attachments/assets/8bbd44c4-0616-425e-82de-8e9e7d653598" />

---

## Security

* AES-256 GCM encryption with unique nonce per file
* Master key stored securely in an environment variable
* No decrypted files stored on disk
* Metadata (IP, filename, timestamp) saved securely
* Token-based access to all routes
* Access logs recorded (access.log)

---

##  Best Practices

* Never commit secrets or keys to your repository
* Use HTTPS (reverse proxy like IIS or nginx)
* Run antivirus scan on uploaded files if deployed
* Rotate the master key periodically (key wrapping recommended)
* Protect the server with rate-limiting and IP restrictions
* Forward logs to a SIEM for audit if needed

---

##  .gitignore Example

Add the following to your .gitignore file to avoid exposing sensitive data:

```
venv/
uploads/
decrypted/
keys/
access.log
*.meta.json
.env
```

---

##  Tech Stack

* Python 3.10+
* Flask
* pycryptodome
* waitress (for Windows production server)

---

##  Authors

Issa Hassan Youssouf
