import os
import io
import secrets
import datetime
import calendar
from datetime import date
import bcrypt
import jwt
from PIL import Image
from fastapi import HTTPException, Request, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ==========================================
# 상수 및 디렉토리 설정
# ==========================================
MAX_UPLOAD_SIZE = 25 * 1024 * 1024
THUMBNAIL_DIR = "./static/img/memberThumb"
MEMBERPHOTO_DIR = "./static/img/members"
CLUBLOGOS_DIR = "./static/img/clubLogos"
GOVLOGOS_DIR = "./static/img/govLogos"
EVENTPHOTO_DIR = "./static/img/event"
DOCPHOTO_DIR = "./static/img/docs"

# ==========================================
# 유틸리티 함수
# ==========================================
def currency(value, symbol="₩", suffix="", places=0):
    if value is None or value == "":
        return ""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return value
    if places == 0:
        formatted = f"{int(round(n)):,}"
    else:
        formatted = f"{n:,.{places}f}"
    return f"{symbol}{formatted}{suffix}"

# 토큰 검증 함수 (API 호출 시마다 실행됨)
async def get_current_mobile_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        memberno: str = payload.get("sub")
        if memberno is None:
            raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")
        return memberno
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다. 다시 로그인해주세요.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="잘못된 토큰입니다.")


# 데이터베이스 세션 생성
async def get_db():
    async with async_session() as session:
        yield session


@app.get("/favicon.ico")
async def favicon():
    return {"detail": "Favicon is served at /static/favicon.ico"}
