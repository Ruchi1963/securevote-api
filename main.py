# main.py
import os
import jwt
import mysql.connector
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from mysql.connector import errorcode
from dotenv import load_dotenv

# Load environment variables (for local dev; Render provides them automatically)
load_dotenv()

app = FastAPI()

# CORS (update with your deployed frontend URL when ready)
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    # "https://your-frontend.onrender.com"  # add your real frontend later
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------
# Database connection
# -------------------
def get_db_connection():
    try:
        return mysql.connector.connect(
            user=os.environ["MYSQL_USER"],
            password=os.environ["MYSQL_PASSWORD"],
            host=os.environ["MYSQL_HOST"],
            port=int(os.environ.get("MYSQL_PORT", 3306)),  # ✅ ensure int
            database=os.environ["MYSQL_DB"],
            connection_timeout=10
        )
    except mysql.connector.Error as err:
        print("DB connection failed:", err)
        raise HTTPException(status_code=500, detail="Database unavailable")


# -------------------
# JWT verification
# -------------------
def verify_token(request: Request):
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )
    token = auth.replace("Bearer ", "")
    try:
        payload = jwt.decode(
            token,
            os.environ["SECRET_KEY"],
            algorithms=["HS256"]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------
# Routes
# -------------------
@app.get("/")
async def root():
    return {"message": "SecureVote backend running"}


@app.get("/login")
async def login(voter_id: str, password: str):
    try:
        cnx = get_db_connection()
        cursor = cnx.cursor()
        cursor.execute(
            "SELECT role FROM voters WHERE voter_id=%s AND password=%s",
            (voter_id, password)
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=401,
                detail="Invalid voter id or password"
            )
        role = row[0]
        cursor.close()
        cnx.close()
    except mysql.connector.Error as err:
        print("DB error in login:", err)
        raise HTTPException(status_code=500, detail="Database error")

    token = jwt.encode(
        {"voter_id": voter_id, "role": role},
        os.environ["SECRET_KEY"],
        algorithm="HS256"
    )
    return {"token": token, "role": role}


@app.get("/protected")
async def protected_route(payload: dict = Depends(verify_token)):
    return {"message": "You are authenticated", "user": payload}
