from pydantic import Field, BaseModel

class HashedFileName(BaseModel):
    # JSON with sha256, sha1, md5
    sha256: str = Field(..., description="SHA256 hash of the file", examples=["1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"])
    md5: str = Field(..., description="MD5 hash of the file", examples=["1234567890abcdef1234567890abcdef"])
    sha1: str = Field(..., description="SHA1 hash of the file", examples=["1234567890abcdef1234567890abcdef"])


class ScannedAnalysisDTO(BaseModel):
    virus_total_id: str = Field(..., description="The VirusTotal ID of the scanned file", examples=["1234567890abcdef1234567890abcdef"])
    scan_status: str = Field(..., description="The status of the scanned file", examples=["completed", "queued"])
    results: dict = Field(..., description="The results of the scan")
    stats: dict = Field(..., description="The stats of the scanned file")
    scan_date: int = Field(..., description="The date of the scan", examples=[1700000000])
    metadata: HashedFileName = Field(..., description="Metadata of the scanned file")
