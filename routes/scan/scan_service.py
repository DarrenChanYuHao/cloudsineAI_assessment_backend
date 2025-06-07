import os
from dotenv import load_dotenv
from fastapi import UploadFile, File
import requests
import magic

# Load environment variables from .env file
load_dotenv()
api_key = os.getenv("VIRUSTOTAL_API_KEY")

'''
 This is the service layer for the scan controller.
 It contains the business logic for virus and malware scanning and uploading files.
'''

def scan_file(file: UploadFile = File(...)):
    """
    Scan a file for viruses and malware.

    1. Check if the file is a valid file type.
    2. Check if the file is under 32MB.
    3. Scan the file for viruses and malware using VirusTotalAPI.
    4. If the file is clean, return the filename.
    """

    MAX_FILE_SIZE_MB = 32 * 1024 * 1024 # 32 MB chosen because it is the free tier limit for VirusTotal API
    MAX_FILE_NAME_LENGTH = 255
    ALLOWED_FILE_TYPES = {
        "image/jpeg",
        "image/png",
        "application/pdf",
        "text/plain",
        "application/zip",
        "application/x-rar-compressed",
        "application/javascript",
    }
    VT_FILEUPLOAD_URL = "https://www.virustotal.com/api/v3/files"


    # First, I santitise the file name and limit number of characters
    if len(file.filename) > MAX_FILE_NAME_LENGTH:
        return {"error": "Filename exceeds maximum length of 255 characters."}

    # Check if the file size exceeds max allowed size
    if file.size > MAX_FILE_SIZE_MB:
        return {"error": f"File size exceeds {MAX_FILE_SIZE_MB}MB limit."}

    # Check if the file type is valid using both file.content_type and python-magic
    if file.content_type not in ALLOWED_FILE_TYPES:
        return {"error" : f"Invalid File Type. Allowed types are: {', '.join(ALLOWED_FILE_TYPES)}."}

    # Use python-magic to verify the file type
    detected_file_type = magic.from_buffer(file.file.read(1024), mime=True)
    file.file.seek(0)

    if detected_file_type not in ALLOWED_FILE_TYPES:
        return {"error" : f"Invalid File Type. Allowed types are: {', '.join(ALLOWED_FILE_TYPES)}."}

    # Check malware and virus using VirusTotalAPI
    files = {
        "file": (file.filename, file.file, file.content_type)
    }
    headers = {
        "accept": "application/json",
        "x-Apikey": api_key
    }

    response = requests.post(url=VT_FILEUPLOAD_URL, headers=headers, files=files)

    if response.status_code != 200:
        return {"error": "Failed to scan file with VirusTotal. Please try again later."}

    # if response.status_code == 200:
    #
    #     # Get analysis results
    #     analysis_results = response.json()

    return response.json()

def analyze_file(file_id: str):
    """
    Analyze a file for viruses and malware.

    1. Check if the file is a valid file type.
    2. Check if the file is under 32MB.
    3. Analyze the file using VirusTotalAPI.
    4. If the file is clean, return the filename.
    """

    VT_ANALYSIS_URL = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url=VT_ANALYSIS_URL, headers=headers)
    return response.json()