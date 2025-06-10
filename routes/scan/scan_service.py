import os
from dotenv import load_dotenv
from fastapi import UploadFile, File, HTTPException
import requests
import puremagic

from routes.scan.DTO.ScannedAnalysisDTO import ScannedAnalysisDTO, HashedFileName
from routes.scan.DTO.ScannedFileDTO import ScannedFileDTO

# Load environment variables from .env file
load_dotenv()
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

# Constants
MAX_FILE_SIZE_MB = 32
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024  # 32 MB chosen because it is the free tier limit for VirusTotal API
MAX_FILE_NAME_LENGTH = 255
ALLOWED_FILE_TYPES = {
    "image/jpeg",
    "image/png",
    "application/pdf",
    "text/plain",
    "text/javascript",
    "application/zip",
    "application/x-rar-compressed",
    "application/javascript",
}
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"

'''
 This is the service layer for the scan controller.
 It contains the business logic for virus and malware scanning and uploading files.
'''

def validate_file(file: UploadFile):
    """
    Validate the uploaded file.
    :param file: UploadFile: The file to validate.
    :return: None
    """

    if len(file.filename) > MAX_FILE_NAME_LENGTH:
        raise HTTPException(status_code=400,
                            detail=f"File name is too long. Maximum length is {MAX_FILE_NAME_LENGTH} characters.")

    # Check if the file size exceeds max allowed size
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File size is too big. Maximum size is {MAX_FILE_SIZE_MB} MB.")

    # Check if the file type is valid using both file.content_type and python-magic
    if file.content_type not in ALLOWED_FILE_TYPES:
        raise HTTPException(status_code=400,
                            detail=f"File content type is {file.content_type}. Allowed types are: " + ", ".join(
                                ALLOWED_FILE_TYPES))

    # # Use python-magic to verify the file type
    # puremagic_response = puremagic.magic_string(file.file.read())
    # detected_file_type = puremagic_response[0].mime_type if puremagic_response else "None"
    # print(detected_file_type)
    # file.file.seek(0)
    #
    # if detected_file_type not in ALLOWED_FILE_TYPES:
    #     raise HTTPException(status_code=400,
    #                         detail=f"File content type is {file.content_type}. Allowed types are: " + ", ".join(
    #                             ALLOWED_FILE_TYPES))

def upload_to_virustotal(file: UploadFile) -> ScannedFileDTO:
    """
    Upload file to VirusTotal for scanning.
    :param file: UploadFile: The file to upload.
    :return: ScannedFileDTO: The scanned file details DTO.
    """
    VT_FILE_UPLOAD_URL = f"{VT_API_BASE_URL}/files"

    files = {
        "file": (file.filename, file.file, file.content_type)
    }
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    response = requests.post(url=VT_FILE_UPLOAD_URL, headers=headers, files=files)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code,
                            detail="Failed to scan file with VirusTotal. Please try again later.")

    response_data = response.json()

    scanned_file = ScannedFileDTO(
        file_name=file.filename,
        file_size=file.size,
        file_type=file.content_type,
        virus_total_id=response_data['data']['id']
    )

    return scanned_file

def scan_file(file: UploadFile = File(...)) -> ScannedFileDTO:
    """
    Scan a file for viruses and malware.
    :param: file: UploadFile: The file to scan.
    :return: ScannedFileDTO: The scanned file details DTO.
    """
    try:

        # Check the file name, type and limit number of characters
        validate_file(file)

        # Check malware and virus using VirusTotalAPI
        scanned_file = upload_to_virustotal(file)

        return scanned_file

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while scanning the file. Please try again later.")

def analyze_file(file_id: str) -> ScannedAnalysisDTO:
    """
    Return analysis of a file for viruses and malware.
    :param file_id: str: The VirusTotal ID of the scanned file.
    :return: ScannedAnalysisDTO: The scanned analysis details DTO.
    """

    VT_ANALYSIS_URL = f"{VT_API_BASE_URL}/analyses/{file_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    analysis_response = requests.get(url=VT_ANALYSIS_URL, headers=headers)

    if analysis_response.status_code != 200:
        raise HTTPException(status_code=analysis_response.status_code,
                            detail="Failed to retrieve file analysis from VirusTotal. Please try again later.")

    VT_FILE_URL = f"{VT_API_BASE_URL}/files/{analysis_response.json()['meta']['file_info']['sha256']}"

    file_response = requests.get(url=VT_FILE_URL, headers=headers)
    if file_response.status_code != 200:
        raise HTTPException(status_code=file_response.status_code,
                            detail="Failed to retrieve file metadata from VirusTotal. Please try again later.")

    print(file_response.json())

    attributes = file_response.json().get('data', {}).get('attributes', {})
    analysis_attributes = analysis_response.json().get('data', {}).get('attributes', {})
    meta_info = analysis_response.json().get('meta', {}).get('file_info', {})

    scanned_analysis = ScannedAnalysisDTO(
        meaningful_name=attributes.get('meaningful_name') or "Pending",
        type_extension=attributes.get('type_extension') or "Pending",
        size=attributes.get('size') or 0,
        last_analysis_date=attributes.get('last_analysis_date') or 0,
        virus_total_id=file_id,
        scan_status=analysis_attributes.get('status'),
        results=analysis_attributes.get('results'),
        stats=analysis_attributes.get('stats'),
        metadata=HashedFileName(
            sha256=meta_info.get('sha256'),
            md5=meta_info.get('md5'),
            sha1=meta_info.get('sha1')
        )
    )

    return scanned_analysis