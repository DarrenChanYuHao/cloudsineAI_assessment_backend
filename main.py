from fastapi import FastAPI
from routes.scan import scan_controller

app = FastAPI()
app.title = "cloudsineAI GenAI Virus and Malware Scanner Backend"

app.include_router(scan_controller.router, tags=["Scan"])