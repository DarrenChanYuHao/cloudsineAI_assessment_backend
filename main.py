from fastapi import FastAPI
from routes.scan import scan_controller
from routes.genai import genai_controller

app = FastAPI()
app.title = "cloudsineAI GenAI Virus and Malware Scanner Backend"

app.include_router(scan_controller.router, tags=["Scan"])
app.include_router(genai_controller.router, tags=["GenAI"])