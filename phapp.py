from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta

import funchub
from funchub import ALGORITHM, JWT_SECRET_KEY, verify_password
from models import Notice, NoticeFile      # 게시판 모델 추가 임포트


router = APIRouter(
    prefix="/phapp",
    tags=["Mobile App API"]
)

security = HTTPBearer()

async def get_db():
    from main import async_session
    async with async_session() as session:
        yield session

# 모바일 앱 전용 JWT 인증 의존성 함수
async def get_current_mobile_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다. 다시 로그인해주세요.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="잘못된 토큰입니다.")


# 요청 데이터 모델 정의
class LoginRequest(BaseModel):
    username: str
    password: str

# ==========================================
# 앱 API 엔드포인트 정의
# ==========================================

@router.post("/mlogin", summary="앱 로그인 및 JWT 발급")
async def app_login(login_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    # 1. 쿼리에 비밀번호 컬럼(memberPw) 추가
    query = text(
        "SELECT memberNo, memberName, activeYN, memberPasswd "
        "FROM chyMember WHERE memberId = :username"
    )
    result = await db.execute(query, {"username": login_data.username})
    user = result.fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")

    # 2. 가져온 데이터에서 stored_password(memberPw) 추출
    user_no, user_name, activeyn, stored_password = user

    # 비밀번호 검증 로직
    authenticated = False
    try:
        # 3. 추출한 stored_password로 검증
        authenticated = verify_password(login_data.password, stored_password)
    except Exception:
        # 해시 암호화가 안 된 평문 비밀번호인 경우를 위한 예외 처리
        if isinstance(stored_password, str) and stored_password.strip() == login_data.password:
            authenticated = True

    if not authenticated:
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")

    # JWT 토큰 생성 (예: 30일 만료)
    expire = datetime.utcnow() + timedelta(days=30)
    payload = {
        "sub": str(user_no),
        "name": user_name,
        "exp": expire
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_info": {
            "userNo": user_no,
            "userName": user_name,
            "activeYN": activeyn
        }
    }


@router.get("/members", summary="회원 목록 조회")
async def get_app_members(
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    member_list = await funchub.get_memberlist(db)
    # SQLAlchemy Row 객체를 JSON 직렬화 가능한 dict로 변환
    return {"members": [dict(row._mapping) for row in member_list]}


@router.get("/memberdtl/{memberno}", summary="회원 목록 조회")
async def get_app_memberdtl(memberno: int,
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    member_dtl = await funchub.get_memberdtl(memberno , db)
    member_info = await funchub.get_memberinfo(memberno, db)
    return {"memberinfo": [dict(row._mapping) for row in member_info], "memberdtl": dict(member_dtl._mapping)}


@router.get("/classes", summary="회원 목록 조회")
async def get_app_classes(
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    class_list = await funchub.get_classlist(db)
    # SQLAlchemy Row 객체를 JSON 직렬화 가능한 dict로 변환
    return {"classes": [dict(row._mapping) for row in class_list]}


@router.get("/class_members/{classno}", summary="회원 목록 조회")
async def get_app_classes(classno: int,
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    class_list = await funchub.get_classmemberlist(db, classno)
    # SQLAlchemy Row 객체를 JSON 직렬화 가능한 dict로 변환
    return {"classmembers": [dict(row._mapping) for row in class_list]}


@router.get("/rank_members", summary="회원 목록 조회")
async def get_all_members(db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    member_list = await funchub.get_rankmemberlist(db)
    # SQLAlchemy Row 객체를 JSON 직렬화 가능한 dict로 변환
    return {"rankmembers": [dict(row._mapping) for row in member_list]}


@router.get("/events", summary="행사 목록 조회")
async def get_app_events(
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    event_list = await funchub.get_eventlist(db)
    return {"events": [dict(row._mapping) for row in event_list]}


@router.get("/events/{eventno}", summary="특정 행사 상세 및 참석자 조회")
async def get_app_event_detail(
        eventno: int,
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    event_dtl = await funchub.get_eventdetail(db, eventno)
    event_members = await funchub.get_eventmemberlist(db, eventno)

    if not event_dtl:
        raise HTTPException(status_code=404, detail="행사를 찾을 수 없습니다.")

    return {
        "event_info": dict(event_dtl._mapping),
        "members": [dict(row._mapping) for row in event_members]
    }


@router.get("/emember_add/{eventno}/{memberno}", summary="특정 행사 상세 및 참석자 조회")
async def add_eventmember(
        memberno: int,eventno:int,
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    try:
        query = text(f"insert into chyEventmember (eventNo, memberNo) values (:eventno, :memberno)")
        await db.execute(query, {"eventno": eventno, "memberno": memberno})
        await db.commit()
        return {"result": "ok"}
    except Exception as e:
        return {"result": "error"}

@router.get("/emember_minus/{eventno}/{memberno}", summary="특정 행사 상세 및 참석자 조회")
async def minus_eventmember(
        memberno: int,eventno:int,
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    try:
        query = text(f"update chyEventmember set attrib = :xxxup where eventNo = :eventno and memberNo = :memberno")
        await db.execute(query, {"eventno": eventno, "memberno": memberno, "xxxup": 'XXXUPXXXUP'})
        await db.commit()
        return {"result": "ok"}
    except Exception as e:
        return {"result": "error"}

# ==========================================
# ★ 신규 추가: 게시판(자료실) 관련 API
# ==========================================

@router.get("/notices", summary="게시판 목록 조회")
async def get_app_notices(
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    # 삭제된 글('XXXUPXXXUP') 제외, 공지사항 우선, 최신순 정렬
    stmt = (
        select(Notice)
        .filter(Notice.attrib != 'XXXUPXXXUP')
        .order_by(Notice.is_notice.desc(), Notice.id.desc())
    )
    result = await db.execute(stmt)
    notices = result.scalars().all()

    # 목록 반환 (내용은 제외하고 가볍게 전송)
    notice_list = []
    for n in notices:
        notice_list.append({
            "id": n.id,
            "title": n.title,
            "author": n.author,
            "is_notice": n.is_notice,
            "view_count": n.view_count,
            "created_at": n.created_at
        })

    return {"notices": notice_list}


@router.get("/notices/{notice_id}", summary="게시판 상세 조회 및 읽기 확인")
async def get_app_notice_detail(
        notice_id: int,
        db: AsyncSession = Depends(get_db),
        current_user: str = Depends(get_current_mobile_user)
):
    # 해당 게시글 및 첨부파일 조회 (삭제된 글 제외)
    stmt = select(Notice).options(selectinload(Notice.files)).filter(
        Notice.id == notice_id,
        Notice.attrib != 'XXXUPXXXUP'
    )
    result = await db.execute(stmt)
    notice = result.scalar_one_or_none()

    if not notice:
        raise HTTPException(status_code=404, detail="삭제되었거나 존재하지 않는 게시글입니다.")

    # 조회수 1 증가 (읽기 확인)
    notice.view_count += 1
    await db.commit()
    await db.refresh(notice)

    # 첨부파일 리스트 정리
    files = []
    for f in notice.files:
        files.append({
            "id": f.id,
            "original_name": f.original_name,
            "saved_name": f.saved_name,
            "file_size": f.file_size,
            "file_url": f"/static/uploads/{f.saved_name}" # 앱에서 다운로드할 수 있는 경로 제공
        })

    return {
        "notice": {
            "id": notice.id,
            "title": notice.title,
            "author": notice.author,
            "content": notice.content, # 상세 조회이므로 본문 포함
            "is_notice": notice.is_notice,
            "view_count": notice.view_count,
            "created_at": notice.created_at
        },
        "files": files
    }
