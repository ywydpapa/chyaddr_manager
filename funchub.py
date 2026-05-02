import os
import io
import datetime
import asyncio
import hashlib
import hmac
import secrets
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException,status,Request,UploadFile,File
from firebase_admin import messaging
from passlib.exc import UnknownHashError
import jwt
import dotenv

dotenv.load_dotenv()

# 상수 설정
MAX_UPLOAD_SIZE = 25 * 1024 * 1024
MEMBERPHOTO_DIR = "./static/img/members"
EVENTPHOTO_DIR = "./static/img/events"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "my_super_secret_mobile_key_1234!")
ALGORITHM = "HS256"

_PBKDF2_ALGORITHM = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 210_000
_PBKDF2_SALT_BYTES = 16
_PBKDF2_KEY_BYTES = 32


def get_password_hash(password: str):
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_PBKDF2_KEY_BYTES,
    )
    return f"{_PBKDF2_ALGORITHM}${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(plain_password: str, hashed_password: str):
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if hashed_password.startswith(f"{_PBKDF2_ALGORITHM}$"):
        try:
            _, iterations_str, salt_hex, digest_hex = hashed_password.split("$", 3)
            iterations = int(iterations_str)
            salt = bytes.fromhex(salt_hex)
            expected_digest = bytes.fromhex(digest_hex)
            actual_digest = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt,
                iterations,
                dklen=len(expected_digest),
            )
            return hmac.compare_digest(actual_digest, expected_digest)
        except Exception:
            return False
    try:
        from passlib.context import CryptContext
        legacy_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
        return legacy_context.verify(plain_password, hashed_password)
    except Exception:
        return False


async def get_current_user(request: Request) -> int:
    user_no = request.session.get("user_No")
    if not user_no:
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="로그인이 필요합니다."
            )
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/"}
        )
    return user_no


async def get_classlist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyClass where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CLASS_LIST)")


async def get_memberlist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyMembers where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(MEMBER_LIST)")


async def get_ranklist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyRank where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(RANK_LIST)")


async def get_memberlist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyMember where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(MEMBER_LIST)")


async def get_memberdtl(memberno:int, db: AsyncSession):
    try:
        query = text("SELECT * FROM chyMember where memberNo = :memberno")
        result = await db.execute(query, {"memberno": memberno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(MEMBER_DETAIL)")


async def get_memberinfo(memberno:int, db: AsyncSession):
    try:
        query = text("SELECT a.*, b.catTitle FROM chyMemberinfo a left join chyCategory b on a.catNo = b.catNo where a.memberNo = :memberno and a.attrib not like '%XXX%'")
        result = await db.execute(query, {"memberno": memberno})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(MEMBER_INFO)")


async def get_catgorylist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyCategory where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CATEGORY_LIST)")


async def get_classlist(db: AsyncSession):
    try:
        query = text("SELECT a.*, COUNT(b.memberNo) AS memberCount FROM chyClass a LEFT JOIN chyClassmember b ON a.classNo = b.classNo where a.attrib not like :attpatt GROUP BY a.classNo")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CLASS_LIST)")


async def get_myclasslist(memberno:int, db: AsyncSession):
    try:
        query = text("SELECT a.*, COUNT(b.memberNo) AS memberCount FROM chyClass a LEFT JOIN chyClassmember b ON a.classNo = b.classNo where a.attrib not like :attpatt GROUP BY a.classNo")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(MY CLASS_LIST)")


async def get_eventlist(db: AsyncSession):
    try:
        query = text("SELECT a.*, COUNT(b.memberNo) AS memberCount FROM chyEvent a LEFT JOIN chyEventmember b ON a.eventNo = b.eventNo where a.attrib not like :attpatt GROUP BY a.eventNo")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CLASS_LIST)")


async def get_companylist(db: AsyncSession):
    try:
        query = text("SELECT a.* FROM chyCompany a where a.attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(COMPANY_LIST)")


async def get_rankdetail(db: AsyncSession, rankno: int):
    try:
        query = text("SELECT * FROM chyRank where rankNo = :rankno")
        result = await db.execute(query, {"rankno": rankno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(RANK_DETAIL)")


async def get_classdetail(db: AsyncSession, classno: int):
    try:
        query = text("SELECT * FROM chyClass where classNo = :classno")
        result = await db.execute(query, {"classno": classno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CLASS_DETAIL)")


async def get_eventdetail(db: AsyncSession, eventno: int):
    try:
        query = text("SELECT * FROM chyEvent where eventNo = :eventno")
        result = await db.execute(query, {"eventno": eventno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(EVENT_DETAIL)")


async def get_categorydetail(db: AsyncSession, catno: int):
    try:
        query = text("SELECT * FROM chyCategory where catNo = :catno")
        result = await db.execute(query, {"catno": catno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CATEGORY_DETAIL)")


async def get_companydetail(db: AsyncSession, compno: int):
    try:
        query = text("SELECT * FROM chyCompany where compNo = :compno")
        result = await db.execute(query, {"compno": compno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(COMPANY_DETAIL)")


async def get_categorybytype(db: AsyncSession, catType: str):
    try:
        query = text("SELECT * FROM chyCategory where catType = :cattype and useYn = 'Y'")
        result = await db.execute(query, {"cattype": catType})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CATEGORY_TYPE)")

async def get_memberdetail(db: AsyncSession, memberno: int):
    try:
        query = text("SELECT * FROM chyMember where memberNo = :memberno")
        result = await db.execute(query, {"memberno": memberno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(MEMBER_DETAIL)")


async def save_memberPhoto(image_data: bytes, memberno: int, size=(200, 300)):
    os.makedirs(MEMBERPHOTO_DIR, exist_ok=True)  # 수정: THUMBNAIL_DIR -> MEMBERPHOTO_DIR
    image = Image.open(io.BytesIO(image_data))
    image.thumbnail(size)
    thumbnail_path = os.path.join(MEMBERPHOTO_DIR, f"mphoto_{memberno}.png")
    image.save(thumbnail_path, format="PNG")
    return thumbnail_path


async def save_eventPhoto(image_data: bytes, eventno: int, size=(200, 300)):
    os.makedirs(EVENTPHOTO_DIR, exist_ok=True)
    image = Image.open(io.BytesIO(image_data))
    image.thumbnail(size)
    thumbnail_path = os.path.join(EVENTPHOTO_DIR, f"ephoto_{eventno}.png") # 수정: MEMBERPHOTO_DIR -> EVENTPHOTO_DIR
    image.save(thumbnail_path, format="PNG")
    return thumbnail_path


async def safe_file_read(file: UploadFile, max_size: int = MAX_UPLOAD_SIZE) -> bytes:
    contents = bytearray()
    while chunk := await file.read(1024 * 1024):
        contents.extend(chunk)
        if len(contents) > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"파일 용량이 너무 큽니다. (최대 {max_size / 1024 / 1024}MB 허용)"
            )
    return bytes(contents)


def row_to_dict(row):
    d = dict(row._mapping)
    for k, v in d.items():
        if isinstance(v, (datetime.date, datetime.datetime)):
            d[k] = v.isoformat()
    return d


async def resize_image_if_needed(contents: bytes, max_bytes: int = 314572) -> bytes:
    if len(contents) <= max_bytes:
        return contents
    image = Image.open(io.BytesIO(contents))
    format = image.format if image.format else 'JPEG'
    quality = 85
    for trial in range(10):
        buffer = io.BytesIO()
        save_kwargs = {'format': format}
        if format.upper() in ['JPEG', 'JPG']:
            save_kwargs['quality'] = quality
            save_kwargs['optimize'] = True
        image.save(buffer, **save_kwargs)
        data = buffer.getvalue()
        if len(data) <= max_bytes:
            return data
        if format.upper() in ['JPEG', 'JPG'] and quality > 30:
            quality -= 10
        else:
            w, h = image.size
            image = image.resize((int(w * 0.9), int(h * 0.9)), Image.LANCZOS)
    return data


async def get_classmemberlist(db: AsyncSession, classno: int):
    try:
        query = text(
            "SELECT lm.*, m.memberName, r.rankTitlekor FROM chyClassmember lm left join chyMember m on lm.memberNo = m.memberNo left join chyRank r on lm.classRank = r.rankNo "
            "where lm.classNo = :classno")
        result = await db.execute(query, {"classno": classno})
        return result.fetchall()
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Database query failed(ClassMemberLIST)")


async def get_eventmemberlist(db: AsyncSession, eventno: int):
    try:
        query = text(
            "SELECT lm.*, m.memberName, r.rankTitlekor, e.eventTitle, f.classNo FROM chyEventmember lm left join chyMember m on lm.memberNo = m.memberNo left join chyRank r on lm.classRank = r.rankNo "
            "LEFT JOIN chyEvent e on lm.eventNo = e.eventNo "
            "LEFT JOIN chyClassmember f on lm.memberNo = f.memberNo "
            "where lm.eventNo = :eventno group by lm.memberNo")
        result = await db.execute(query, {"eventno": eventno})
        return result.fetchall()
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Database query failed(EventMemberLIST)")