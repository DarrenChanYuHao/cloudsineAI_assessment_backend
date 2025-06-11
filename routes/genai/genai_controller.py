from fastapi import APIRouter

from routes.scan.DTO.ScannedAnalysisDTO import ScannedAnalysisDTO
from routes.genai import genai_service

router = APIRouter(
    prefix="/genai",
)


@router.get("/test")
def test() -> str:
    """
    Test that Gemini API is working.

    :return: str: A simple response indicating the service is running.
    """
    return genai_service.test_genai()

@router.post("/summarize_result", summary="Take VirusTotal result and summarize it")
def summarize_result(result: ScannedAnalysisDTO, system_prompt_type: str) -> dict:
    """
    Summarize the result of VirusTotal Analysis.

    This endpoint takes a dictionary containing the result from VirusTotal analysis
    and returns a layman summary of the findings.

    :param result: dict: The VirusTotal result to summarize.
    :param system_prompt_type: str: The type of system prompt to use for summarization.
    :return: dict: The summarized result.
    """

    return genai_service.summarize_result(result, system_prompt_type)