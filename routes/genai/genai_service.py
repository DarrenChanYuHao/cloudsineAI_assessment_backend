import os
from dotenv import load_dotenv
from google import genai
from google.genai import types
import json

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

def summarize_result(report: ScannedAnalysisDTO) -> dict:
    """
    Summarize the result of VirusTotal Analysis.
    :param report: dict: The VirusTotal report to summarize.
    :return:
    """

    system_prompt = '''
    You are a cybersecurity assistant helping non-technical users understand malware scan results.

    The user will provide a JSON report from VirusTotal containing a scan summary of a file. Your job is to analyze the information and explain it in simple, non-technical terms.
    
    Assume the user does not know what an antivirus engine is or what a SHA256 hash means.

    ---

    Your response must follow this structure:
    
    Here's a breakdown of the VirusTotal scan results for your file {replace with virus_total_id here}:
    
    1. 📄 **Summary**: Was the file safe or suspicious? Mention the total number of antivirus engines used and how many flagged it.

    2. 🔍 **Scan Highlights**:
       - Did any engines detect the file as malicious or suspicious?
       - Were there timeouts or unsupported results?
       - Mention if the majority agreed on the result.

    3. 🛡 **What This Means** (Layman's terms):
       - Explain whether the user should feel safe opening this file.
       - If not safe, explain the virus or malware type in simple terms. Limit to one sentence.
       - If not safe, give one simple action (e.g., “This file contains virus. Do not open this file and delete it.”)

    4. 🧾 **File Metadata**:
       - Show SHA256 and scan date (convert UNIX timestamp to readable date).
       - This helps users keep a record.

    5. 🗒 **Optional Technical Insight** (brief and simple):
       - Any notable observations or anomalies across the engines.

    ---

    Respond clearly and avoid including any raw JSON and code in your answer.
    '''

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
            system_instruction=system_prompt),
        contents=user_prompt,
    )

    if not response:
        return {"summary": "No response from Gemini API"}

    return {"summary": response.text} if response.text else {"summary": "No summary generated"}

