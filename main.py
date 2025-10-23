from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from datetime import timedelta, datetime
import pandas as pd
import uuid

#env/Scripts/activate
#pip install -r suprim.txt
#uvicorn main:app --reload

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
# app.mount("/sources", StaticFiles(directory="sources"), name="sources")
templates = Jinja2Templates(directory="templates")
USERS = "users.csv"
SESSION_TTL = timedelta(10)
sessions = {}
white_urls = ["/", "/login", "/logout"]

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    return templates.TemplateResponse("login.html",{"request":request})

@app.post("/login")
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):


    users = pd.read_csv(USERS)

    if username in users['user'].tolist():
        stored_password = str(users.loc[users['user'] == username, 'password'].values[0])
        if stored_password == password:
            session_id = str(uuid.uuid4())
            sessions[session_id] = datetime.now()
            response = RedirectResponse(url="/main", status_code=302)
            response.set_cookie(key="session_id", value=session_id, httponly=True)
            return response

    return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Ошибка сервера. Попробуйте позже."
        })

@app.get("/main", response_class=HTMLResponse)
def get_main_page(request: Request):
    return templates.TemplateResponse("main.html", {"request": request})

