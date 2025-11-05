import magic
import os
import argparse
import hashlib

def file_hash(filepath, algorithm):
    # Compute and return the hash of a file using the specified algorithm
    hash_obj = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def check_extension_match_using_magic(filepath):
    # Create a magic object
    mime = magic.Magic(mime=True)
    actual_mime_type = mime.from_file(filepath)
    file_extension = os.path.splitext(filepath)[1]

    # You may need to map more MIME types to extensions based on your requirements
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

    # Reverse the dictionary to get extensions from MIME types
    mime_to_extension = {v: k for k, v in extension_to_mime.items()}

    expected_extension = mime_to_extension.get(actual_mime_type)
    if expected_extension == file_extension:
        print(f"The file extension {file_extension} matches the actual MIME type: {actual_mime_type}")
    else:
        print(f"Mismatch detected: The actual MIME type {actual_mime_type} does not match the file extension {file_extension}. Expected extension: {expected_extension}")

    # Compute and print MD5 and SHA-256 hashes
    md5_hash = file_hash(filepath, 'md5')
    sha256_hash = file_hash(filepath, 'sha256')
    print(f"\nMD5: {md5_hash}\n")
    print(f"SHA-256: {sha256_hash}\n")

def main():
    # Create an argument parser
    parser = argparse.ArgumentParser(description="Check if a file's MIME type matches its extension.")
    parser.add_argument('filepath', type=str, help='Path to the file to check.')

    # Parse arguments
    args = parser.parse_args()

    # Run the check
    check_extension_match_using_magic(args.filepath)

if __name__ == '__main__':
    main()

