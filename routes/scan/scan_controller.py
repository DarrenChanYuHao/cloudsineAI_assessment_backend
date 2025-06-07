from fastapi import APIRouter, UploadFile, File
from routes.scan import scan_service
from routes.scan.DTO.ScannedAnalysisDTO import ScannedAnalysisDTO
from routes.scan.DTO.ScannedFileDTO import ScannedFileDTO

router = APIRouter(
    prefix="/scan",
)

@router.post("/scan_file", response_model=ScannedFileDTO)
def scan_file(file: UploadFile = File(...)) -> ScannedFileDTO:

    """
    Scan a file for viruses and malware.

    1. Check if the file is a valid file type.
    2. Check if the file is under 32MB.
    3. Scan the file for viruses and malware.
    4. If the file is clean, return the filename.
    """

    return scan_service.scan_file(file)

@router.get("/analyze")
def analyze_file(file_id: str) -> ScannedAnalysisDTO:
    """
    Return analysis of a file for viruses and malware.
    """

    return scan_service.analyze_file(file_id)