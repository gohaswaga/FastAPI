from fastapi import FastAPI, Form, Request, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import HTTPException
from datetime import datetime, timedelta
import pandas as pd
import uuid
import hashlib
import logging
import os

# Настройка логирования
logging.basicConfig(
    filename="log.csv",
    level=logging.INFO,
    format="%(asctime)s,%(levelname)s,%(message)s",
    encoding="utf-8"
)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

USERS = "users.csv"
SESSION_TTL = timedelta(minutes=10)
sessions = {}
white_urls = ["/", "/login", "/logout", "/register"]

ADMIN_USER = "admin"
ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

if not os.path.exists(USERS):
    df = pd.DataFrame(columns=["user", "password"])
    df = pd.concat([df, pd.DataFrame([[ADMIN_USER, ADMIN_PASSWORD_HASH]], columns=["user", "password"])], ignore_index=True)
    df.to_csv(USERS, index=False)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

@app.middleware("http")
async def check_session(request: Request, call_next):
    if request.url.path.startswith("/static") or request.url.path in white_urls:
        return await call_next(request)

    session_id = request.cookies.get("session_id")
    session_data = sessions.get(session_id)

    if not session_data or datetime.now() - session_data["created"] > SESSION_TTL:
        sessions.pop(session_id, None)
        return RedirectResponse(url="/")

    logging.info(f"SESSION ACTIVE: {session_id} ({session_data['user']})")
    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/main/admin", response_class=HTMLResponse)
def get_main_page(request: Request):
    return templates.TemplateResponse("main.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/home", response_class=HTMLResponse)
def get_home_page(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/404", response_class=HTMLResponse)
def get_404_page(request: Request):
    return templates.TemplateResponse("404.html", {"request": request})

@app.get("/403", response_class=HTMLResponse)
def get_403_page(request: Request):
    return templates.TemplateResponse("403.html", {"request": request})

@app.post("/login")
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):
    users = pd.read_csv(USERS, dtype=str)
    user_row = users.loc[users["user"].str.strip() == username.strip()]

    if not user_row.empty:
        stored_hash = str(user_row.iloc[0]["password"]).strip()
        if verify_password(password.strip(), stored_hash):
            session_id = str(uuid.uuid4())
            sessions[session_id] = {
                "created": datetime.now(),
                "user": username
            }
            logging.info(f"LOGIN: {username}, session_id={session_id}")
            response = RedirectResponse(url='/main/admin', status_code=302)
            response.set_cookie(
                key="session_id",
                value=session_id,
                httponly=True,
                max_age=int(SESSION_TTL.total_seconds())
            )
            return response

    logging.warning(f"LOGIN FAILED: {username}")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Неверный логин или пароль"
    })

@app.post("/register")
async def register(request: Request,
                   username: str = Form(...),
                   password: str = Form(...),
                   avatar: UploadFile = File(None)):

    users = pd.read_csv(USERS)

    if username == ADMIN_USER:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Имя пользователя зарезервировано"
        })

    if username in users['user'].values:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь уже существует"
        })

    if avatar:
        os.makedirs("static/avatars", exist_ok=True)
        unique_name = f"{username}_{uuid.uuid4().hex}_{avatar.filename}"
        avatar_path = os.path.join("static/avatars", unique_name)
        with open(avatar_path, "wb") as f:
            f.write(await avatar.read())

    hashed_password = hash_password(password)
    new_user = pd.DataFrame([[username, hashed_password]], columns=["user", "password"])
    users = pd.concat([users, new_user], ignore_index=True)
    users.to_csv(USERS, index=False)

    logging.info(f"REGISTER: {username}")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "message": "Регистрация успешна. Теперь войдите."
    })

@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    user = sessions.get(session_id, {}).get("user", "unknown")
    sessions.pop(session_id, None)
    logging.info(f"LOGOUT: {user}, session_id={session_id}")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "message": "Сессия завершена"
    })

@app.exception_handler(404)
async def not_found_page(request: Request, exc):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        return RedirectResponse(url="/404")
    else:
        return RedirectResponse(url="/")

@app.exception_handler(403)
async def forbidden_page(request: Request, exc):
    return RedirectResponse(url="/403")
