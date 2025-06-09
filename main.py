from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.scan import scan_controller
from routes.genai import genai_controller

app = FastAPI()
app.title = "cloudsineAI Take Home Assignment: GenAI Virus and Malware Scanner Backend"

origins = [
    "http://localhost:4321",  # Astro local dev server
    "https://cai.darrenchanyuhao.com",  # Public frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_controller.router, tags=["Scan"])
app.include_router(genai_controller.router, tags=["GenAI"])