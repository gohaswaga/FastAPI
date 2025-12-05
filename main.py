from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from typing import Optional, Dict
import uuid
import pandas as pd
from datetime import datetime, timedelta
import hashlib
import os
import csv
import uvicorn

class Config:
    USERS_CSV = 'data/users.csv'
    LOGS_CSV = 'data/logs.csv'
    SESSION_TTL = timedelta(minutes=30)
    ADMIN_LOGIN = "admin"
    ADMIN_PASSWORD = "12345"
    WHITE_URLS = {"/", "/login", "/logout", "/register"}

class UserService:
    def __init__(self, config: Config):
        self.config = config
        self._ensure_data_directory()
        self._ensure_admin_user()

    def _ensure_data_directory(self):
        os.makedirs('data', exist_ok=True)

    def _ensure_admin_user(self):
        if not os.path.exists(self.config.USERS_CSV):
            df = pd.DataFrame(columns=["username", "password", "role", "created_at"])
            df.to_csv(self.config.USERS_CSV, index=False, encoding="utf-8")

        users = self.get_all_users()
        if self.config.ADMIN_LOGIN not in users["username"].values:
            admin_hash = self._hash_password(self.config.ADMIN_PASSWORD)
            new_admin = pd.DataFrame([[
                self.config.ADMIN_LOGIN, 
                admin_hash, 
                "admin",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ]], columns=["username", "password", "role", "created_at"])
            
            users = pd.concat([users, new_admin], ignore_index=True)
            users.to_csv(self.config.USERS_CSV, index=False, encoding="utf-8")
            self.write_log("INFO", "Создан администратор по умолчанию", self.config.ADMIN_LOGIN)

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def get_all_users(self) -> pd.DataFrame:
        if os.path.exists(self.config.USERS_CSV):
            return pd.read_csv(self.config.USERS_CSV, encoding="utf-8")
        return pd.DataFrame(columns=["username", "password", "role", "created_at"])

    def get_user(self, username: str) -> Optional[dict]:
        users = self.get_all_users()
        user_data = users[users["username"] == username]
        
        if user_data.empty:
            return None
            
        return {
            "username": user_data["username"].values[0],
            "password": user_data["password"].values[0],
            "role": user_data["role"].values[0],
            "created_at": user_data["created_at"].values[0]
        }

    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        users = self.get_all_users()
        
        if username in users["username"].values:
            return False
            
        hashed_password = self._hash_password(password)
        new_user = pd.DataFrame([[
            username, 
            hashed_password, 
            role,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ]], columns=["username", "password", "role", "created_at"])
        
        users = pd.concat([users, new_user], ignore_index=True)
        users.to_csv(self.config.USERS_CSV, index=False, encoding="utf-8")
        return True

    def verify_user(self, username: str, password: str) -> bool:
        user = self.get_user(username)
        if not user:
            return False
            
        hashed_password = self._hash_password(password)
        return user["password"] == hashed_password

    def get_users_count(self) -> int:
        users = self.get_all_users()
        return len(users)

    def write_log(self, level: str, event: str, username: str = "", extra: str = ""):
        file_exists = os.path.exists(self.config.LOGS_CSV)
        with open(self.config.LOGS_CSV, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "level", "event", "username", "extra"])
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                level, event, username, extra
            ])

    def get_recent_logs(self, limit: int = 50) -> list:
        if not os.path.exists(self.config.LOGS_CSV):
            return []
        
        logs_df = pd.read_csv(self.config.LOGS_CSV, encoding="utf-8")
        return logs_df.tail(limit).to_dict('records')

class SessionManager:
    def __init__(self, ttl: timedelta):
        self.sessions: Dict[str, dict] = {}
        self.ttl = ttl

    def create_session(self, username: str) -> str:
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "created": datetime.now(),
            "username": username
        }
        return session_id

    def get_username(self, session_id: str) -> Optional[str]:
        if not session_id or session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        if datetime.now() - session["created"] > self.ttl:
            del self.sessions[session_id]
            return None
            
        session["created"] = datetime.now()
        return session["username"]

    def delete_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]

config = Config()
user_service = UserService(config)
session_manager = SessionManager(config.SESSION_TTL)

app = FastAPI(title="Auth System", version="2.0.0")

app.mount('/static', StaticFiles(directory='static'), name='static')
templates = Jinja2Templates(directory="templates")

def get_current_user(request: Request) -> Optional[str]:
    session_id = request.cookies.get('session_id')
    return session_manager.get_username(session_id) if session_id else None

def require_auth(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user

def require_admin(user: str = Depends(require_auth)):
    user_data = user_service.get_user(user)
    if not user_data or user_data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return user

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    
    if (path.startswith('/static') or 
        path in config.WHITE_URLS or 
        path.startswith("/main")):
        return await call_next(request)

    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login')

    response = await call_next(request)
    return response

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "users_count": user_service.get_users_count()
    })

@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return templates.TemplateResponse("login.html", {
            'request': request,
            'error': 'Логин и пароль обязательны',
            'users_count': user_service.get_users_count()
        }, status_code=200)

    if user_service.verify_user(username, password):
        session_id = session_manager.create_session(username)
        response = RedirectResponse(url=f"/welcome/{username}", status_code=302)
        response.set_cookie(key='session_id', value=session_id)
        user_service.write_log("INFO", "Успешный вход в систему", username)
        return response

    error = "Неверный логин или пароль"
    user_service.write_log("WARNING", "Неудачная попытка входа", username)
    return templates.TemplateResponse(
        "login.html",
        {
            'request': request, 
            'error': error,
            'users_count': user_service.get_users_count()
        },
        status_code=200
    )

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("registr.html", {
        "request": request,
        "users_count": user_service.get_users_count()
    })

@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    admin_login: str = Form(...),
    admin_password: str = Form(...)
):
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return templates.TemplateResponse("registr.html", {
            "request": request,
            "error": "Логин и пароль обязательны",
            "users_count": user_service.get_users_count()
        }, status_code=200)

    if (admin_login != config.ADMIN_LOGIN or 
        admin_password != config.ADMIN_PASSWORD):
        return templates.TemplateResponse("registr.html", {
            "request": request,
            "error": "Неверные данные администратора",
            "users_count": user_service.get_users_count()
        }, status_code=200)

    if user_service.get_user(username):
        return templates.TemplateResponse("registr.html", {
            "request": request,
            "error": "Пользователь уже существует",
            "users_count": user_service.get_users_count()
        }, status_code=200)

    role = "admin" if username == config.ADMIN_LOGIN else "user"
    if user_service.create_user(username, password, role):
        session_id = session_manager.create_session(username)
        response = RedirectResponse(url=f"/welcome/{username}", status_code=302)
        response.set_cookie(key="session_id", value=session_id)
        user_service.write_log("INFO", "Успешная регистрация", username)
        return response

    return templates.TemplateResponse("registr.html", {
        "request": request,
        "error": "Ошибка при создании пользователя",
        "users_count": user_service.get_users_count()
    }, status_code=200)

@app.get("/welcome/{username}", response_class=HTMLResponse)
def welcome_page(request: Request, username: str, current_user: str = Depends(require_auth)):
    if current_user != username:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    user_data = user_service.get_user(username)
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    return templates.TemplateResponse("welcome.html", {
        'request': request,
        'username': username,
        'user_data': user_data,
        'users_count': user_service.get_users_count()
    })

@app.get("/main/{username}", response_class=HTMLResponse)
def admin_panel(request: Request, username: str, admin: str = Depends(require_admin)):
    if admin != username:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    users = user_service.get_all_users()
    recent_logs = user_service.get_recent_logs(20)

    return templates.TemplateResponse("main.html", {
        "request": request, 
        "username": username,
        "users": users.to_dict('records'),
        "recent_logs": recent_logs,
        "users_count": len(users),
        "logs_count": len(recent_logs)
    })

@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        username = session_manager.get_username(session_id)
        session_manager.delete_session(session_id)
        if username:
            user_service.write_log("INFO", "Выход из системы", username)

    response = RedirectResponse(url="/login")
    response.delete_cookie("session_id")
    return response

@app.get("/api/users")
def get_users_api(admin: str = Depends(require_admin)):
    users = user_service.get_all_users()
    return users.to_dict('records')

@app.get("/api/logs")
def get_logs_api(admin: str = Depends(require_admin)):
    logs = user_service.get_recent_logs(100)
    return logs

@app.exception_handler(404)
def not_found_handler(request: Request, exc):
    return templates.TemplateResponse("404.html", {
        "request": request,
        "users_count": user_service.get_users_count()
    }, status_code=404)

@app.exception_handler(403)
def forbidden_handler(request: Request, exc):
    return templates.TemplateResponse("403.html", {
        "request": request,
        "users_count": user_service.get_users_count()
    }, status_code=403)

@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc):
    return PlainTextResponse("Ошибка запроса", status_code=400)

if __name__ == "__main__":
    mode = os.getenv("APP_MODE", "prod")
    
    if mode == "test":
        uvicorn.run(
            "main:app", 
            host="127.0.0.1", 
            port=8000, 
            reload=True
        )
    else:
        uvicorn.run(
            "main:app",
            host="127.0.0.1",
            port=443,
            ssl_certfile="cert.pem",
            ssl_keyfile="key.pem",
        )
