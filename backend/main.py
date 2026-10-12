# CyberShield AI - FastAPI backend
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from routes import auth, events, threats, investigate, respond, audit, devices, collect

app = FastAPI(title="CyberShield AI", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(investigate.router, prefix="/api")
app.include_router(respond.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(collect.router, prefix="/api")

FRONT = Path(__file__).resolve().parents[1] / "frontend"

@app.get("/api/health")
def health():
    return {"ok": True, "msg": "CyberShield AI running"}

# serve simple HTML frontend
if FRONT.exists():
    app.mount("/css", StaticFiles(directory=FRONT / "css"), name="css")
    app.mount("/js", StaticFiles(directory=FRONT / "js"), name="js")

    @app.get("/")
    def home():
        return FileResponse(FRONT / "index.html")

    @app.get("/login")
    def login_page():
        return FileResponse(FRONT / "login.html")

    @app.get("/events")
    def events_page():
        return FileResponse(FRONT / "events.html")

    @app.get("/threats")
    def threats_page():
        return FileResponse(FRONT / "threats.html")

    @app.get("/investigations")
    def inv_page():
        return FileResponse(FRONT / "investigations.html")

    @app.get("/audit")
    def audit_page():
        return FileResponse(FRONT / "audit.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
