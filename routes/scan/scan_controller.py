from fastapi import APIRouter, UploadFile, File
from typing import Optional
from routes.scan import scan_service

router = APIRouter(
    prefix="/scan",
)

@router.post("/scan_file")
def scan_file(file: UploadFile = File(...)):

    """
    Scan a file for viruses and malware.

    1. Check if the file is a valid file type.
    2. Check if the file is under 32MB.
    3. Scan the file for viruses and malware.
    4. If the file is clean, return the filename.
    """

    return scan_service.scan_file(file)

@router.post("/upload_file")
def upload_file(file: UploadFile = File(...)):
    """
    Upload a file to the server.

    1. Check if the file is a valid file type.
    2. Check if the file is under 32MB.
    3. Save the file to the server.
    4. Return the filename.
    """

    return 1

@router.get("/analyze")
def analyze_file(file_id: str):
    """
    Return analysis of a file for viruses and malware.
    """

    return scan_service.analyze_file(file_id)