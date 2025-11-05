from flask import Flask, request, render_template, make_response, send_from_directory
from werkzeug.utils import secure_filename, safe_join
import magic
import os
import hashlib

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# limit max file size
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# computes the hash of a file
def file_hash(filepath, algorithm):
    hash_obj = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

# verifies file extension
def check_extension_match_using_magic(file_storage):
    # check if the upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_storage.filename)
    file_storage.save(filepath)

    # get file size
    file_size = os.path.getsize(filepath) 
    print(f"File Size: {file_size} bytes")

    # use magic library to determine actual MIME extension of the function
    mime = magic.Magic(mime=True)
    # actual file extension
    actual_mime_type = mime.from_file(filepath)
    # received file extension
    file_extension = os.path.splitext(file_storage.filename)[1]

    # extension to MIME type mapping
    extension_to_mime = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.pdf': 'application/pdf',
        '.txt': 'text/plain',
        '.html': 'text/html',
        '.htm': 'text/html',
        '.csv': 'text/csv',
        '.xls': 'application/vnd.ms-excel',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.ppt': 'application/vnd.ms-powerpoint',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        '.mp3': 'audio/mpeg',
        '.wav': 'audio/x-wav',
        '.mp4': 'video/mp4',
        '.avi': 'video/x-msvideo',
        '.mov': 'video/quicktime',
        '.zip': 'application/zip',
        '.rar': 'application/x-rar-compressed',
        '.7z': 'application/x-7z-compressed',
        '.xml': 'application/xml',
        '.json': 'application/json',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.php': 'text/php',
        '.py': 'text/x-python',
        '.java': 'text/x-java-source',
        '.c': 'text/x-c',
        '.cpp': 'text/x-c',
        '.h': 'text/x-c',
        '.sql': 'application/sql',
    }

    mime_to_extension = {v: k for k, v in extension_to_mime.items()}
    
    expected_extension = mime_to_extension.get(actual_mime_type)

    match_result = expected_extension == file_extension

    md5_hash = file_hash(filepath, 'md5')
    sha256_hash = file_hash(filepath, 'sha256')

    # remove uploaded file after processing
    os.remove(filepath)

    # output of program
    return {
        'match_result': match_result,
        'file_extension': file_extension,
        'actual_mime_type': actual_mime_type,
        'expected_extension': expected_extension,
        'md5_hash': md5_hash,
        'sha256_hash': sha256_hash,
        'file_size': file_size
    }

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    
    # file name sanitization
    file.filename = secure_filename(file.filename)

    # file extension check
    if file:
        result = check_extension_match_using_magic(file)
        return render_template('results.html', result=result)

# security headers to protect against common web vulnerabilities
@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Feature-Policy"] = "geolocation 'self'; vibrate 'none'"
    return response

# run debug in false to protect sensitive information
if __name__ == '__main__':
    app.run(debug=False)
