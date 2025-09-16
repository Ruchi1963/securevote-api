# main.py
import os

import dotenv
import jwt
import mysql.connector
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from mysql.connector import errorcode

dotenv.load_dotenv()
app = FastAPI()

# Add your frontend URL(s) here after deploying frontend
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    return mysql.connector.connect(
        user=os.environ['MYSQL_USER'],
        password=os.environ['MYSQL_PASSWORD'],
        host=os.environ['MYSQL_HOST'],
        port=int(os.environ.get('MYSQL_PORT', 3306)),
        database=os.environ['MYSQL_DB'],
        connection_timeout=10
    )

# optional initial cursor
try:
    cnx = get_db_connection()
    cursor = cnx.cursor()
except Exception as e:
    print("Initial DB connection failed:", e)
    cursor = None

@app.get("/")
async def root():
    return {"message": "SecureVote backend running"}

def verify_token(request: Request):
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    token = auth.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, os.environ['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.get("/login")
async def login(voter_id: str, password: str):
    global cursor, cnx
    if cursor is None:
        cnx = get_db_connection(); cursor = cnx.cursor()
    try:
        cursor.execute("SELECT role FROM voters WHERE voter_id=%s AND password=%s", (voter_id, password))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid voter id or password")
        role = row[0]
    except mysql.connector.Error as err:
        print("DB error in login:", err)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    token = jwt.encode({'voter_id': voter_id, 'role': role}, os.environ['SECRET_KEY'], algorithm='HS256')
    return {'token': token, 'role': role}

@app.get("/protected")
async def protected_route(payload: dict = Depends(verify_token)):
    return {"message": "You are authenticated", "user": payload}
