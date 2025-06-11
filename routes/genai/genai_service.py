import os
from dotenv import load_dotenv
from google import genai
from google.genai import types
import json

from routes.genai import system_prompt_variations
from routes.scan.DTO.ScannedAnalysisDTO import ScannedAnalysisDTO

# Load environment variables from .env file
load_dotenv()
gemini_api_key = os.getenv("GEMINI_API_KEY")

# Constants

# Functions
def test_genai() -> str:
    """
    Test the Gemini API connection with a simple query.
    :return: str: Simple response from the Gemini API.
    """

    client = genai.Client(api_key=gemini_api_key)
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents="Explain how AI works in a few words",
    )

    return response.text if response else "No response from Gemini API"

def summarize_result(report: ScannedAnalysisDTO, system_prompt_type: str) -> dict:
    """
    Summarize the result of VirusTotal Analysis.
    :param report: dict: The VirusTotal report to summarize
    :param system_prompt_type: str: The type of system prompt to use for summarization.
    :return:
    """

    system_prompt = system_prompt_variations.get_system_prompt(system_prompt_type)
    user_prompt = f'''
    Here is the VirusTotal report:
    ```
    {report}
    ```
    '''

    client = genai.Client(api_key=gemini_api_key)
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type='text/plain'),
        contents=user_prompt,
    )

    if not response:
        return {"summary": "No response from Gemini API"}

    return {"summary": response.text} if response.text else {"summary": "No summary generated"}

