from fastapi import APIRouter

from routes.scan.DTO.ScannedAnalysisDTO import ScannedAnalysisDTO

router = APIRouter(
    prefix="/genai",
)

@router.post("/summarize_result", summary="Take VirusTotal result and summarize it")
def summarize_result(result: ScannedAnalysisDTO) -> dict:
    """
    Summarize the result of VirusTotal Analysis.

    This endpoint takes a dictionary containing the result from VirusTotal analysis
    and returns a layman summary of the findings.

    :param result: dict: The VirusTotal result to summarize.
    :return: dict: The summarized result.
    """

    return {"summary": "This is a summarized result."}