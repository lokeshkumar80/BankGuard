"""FastAPI application entry point for BankGuard -- registers all routers and initializes the DB."""
import logging

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from dashboard.routes import router as dashboard_router
from db.models import init_db

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="BankGuard - Financial Security Intelligence System")
app.include_router(dashboard_router)


@app.on_event("startup")
def on_startup() -> None:
    """Initialize the SQLite database schema when the app starts."""
    init_db()


@app.get("/")
def root() -> RedirectResponse:
    """Redirect the index route to the login page."""
    return RedirectResponse(url="/login")
