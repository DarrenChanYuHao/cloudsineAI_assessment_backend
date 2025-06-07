from pydantic import BaseModel, HttpUrl, Field

class ScannedFileDTO(BaseModel):
    file_name: str = Field(..., description="The name of the scanned file", examples=["example.txt"])
    file_size: int = Field(..., description="The size of the scanned file in bytes", examples=[123456])
    file_type: str = Field(..., description="The MIME type of the scanned file", examples=["text/plain"])
    virus_total_id: str = Field(..., description="The VirusTotal ID of the scanned file", examples=["1234567890abcdef1234567890abcdef"])