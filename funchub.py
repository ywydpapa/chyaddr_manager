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
from fastapi import HTTPException
from firebase_admin import messaging
from passlib.exc import UnknownHashError
import jwt
import dotenv

dotenv.load_dotenv()

# 상수 설정
MPHOTO_DIR = "./static/img/members"
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


async def get_catgorylist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyCategory where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CATEGORY_LIST)")


async def get_classlist(db: AsyncSession):
    try:
        query = text("SELECT * FROM chyClass where attrib not like :attpatt")
        result = await db.execute(query, {"attpatt": "%XXX%"})
        return result.fetchall()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CLASS_LIST)")


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


async def get_categorydetail(db: AsyncSession, catno: int):
    try:
        query = text("SELECT * FROM chyCategory where catNo = :catno")
        result = await db.execute(query, {"catno": catno})
        return result.fetchone()
    except Exception:
        raise HTTPException(status_code=500, detail="Database query failed(CATEGORY_DETAIL)")


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