import os
import uuid
import shutil
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func
from database import get_db
from models import Notice, NoticeFile

# prefix 없이 깔끔하게 라우터 생성
router = APIRouter()
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ==========================================
# 1. 공지사항 목록 보기 (GET)
# ==========================================
@router.get("/notice")
async def get_notice_list(request: Request, db: AsyncSession = Depends(get_db)):
    # 총 게시물 수 구하기 (삭제된 글 'XXXUPXXXUP' 제외)
    result_count = await db.execute(
        select(func.count(Notice.id)).filter(Notice.attrib != 'XXXUPXXXUP')
    )
    total_count = result_count.scalar()

    # 게시글 목록 가져오기 (삭제된 글 제외, 공지사항 우선, 최신순)
    stmt = (
        select(Notice)
        .options(selectinload(Notice.files))
        .filter(Notice.attrib != 'XXXUPXXXUP')
        .order_by(Notice.is_notice.desc(), Notice.id.desc())
    )
    result = await db.execute(stmt)
    notices = result.scalars().all()

    return templates.TemplateResponse(
        request=request,
        name="/mst/mst_notice.html",
        context={"request": request, "notices": notices, "total_count": total_count}
    )


# ==========================================
# 2. 글쓰기 화면 보여주기 (GET)
# ==========================================
@router.get("/new_notice")
async def write_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="/mst/new_notice.html",
        context={"request": request}
    )


# ==========================================
# 3. 글쓰기 폼 전송 및 DB 저장 (POST)
# ==========================================
@router.post("/new_notice")
async def upload_board(
        request: Request,
        title: str = Form(...),
        author: str = Form(...),
        content: str = Form(...),
        password: str = Form(...),
        noticeCheck: Optional[str] = Form(None),
        files: List[UploadFile] = File(None),
        db: AsyncSession = Depends(get_db)
):
    is_notice = 'Y' if noticeCheck == 'Y' else 'N'

    # 1) 텍스트 데이터 DB 저장 (attrib는 기본값으로 저장됨)
    new_notice = Notice(
        title=title,
        author=author,
        password=password,
        content=content,
        is_notice=is_notice
    )
    db.add(new_notice)
    await db.commit()
    await db.refresh(new_notice)

    # 2) 첨부파일 저장 처리
    if files:
        for file in files:
            if file.filename == "":
                continue

            original_name = file.filename
            ext = os.path.splitext(original_name)[1]
            saved_name = f"{uuid.uuid4().hex}{ext}"
            file_path = os.path.join(UPLOAD_DIR, saved_name)

            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            file_size = os.path.getsize(file_path)

            new_file = NoticeFile(
                notice_id=new_notice.id,
                original_name=original_name,
                saved_name=saved_name,
                file_path=file_path,
                file_size=file_size
            )
            db.add(new_file)

        await db.commit()

    # 3) 저장이 완료되면 목록 페이지로 이동
    return RedirectResponse(url="/notice", status_code=303)


# ==========================================
# 4. 게시글 상세 보기 (GET)
# ==========================================
@router.get("/notice/{notice_id}")
async def get_notice_detail(request: Request, notice_id: int, db: AsyncSession = Depends(get_db)):
    # 1) DB에서 해당 번호의 글 가져오기 (삭제된 글 접근 불가 처리)
    stmt = select(Notice).options(selectinload(Notice.files)).filter(
        Notice.id == notice_id,
        Notice.attrib != 'XXXUPXXXUP'
    )
    result = await db.execute(stmt)
    notice = result.scalar_one_or_none()

    if not notice:
        return HTMLResponse("<script>alert('삭제되었거나 존재하지 않는 게시글입니다.'); location.href='/notice';</script>")

    # 2) 조회수 1 증가시키기
    notice.view_count += 1
    await db.commit()
    await db.refresh(notice)

    # 3) 상세 보기 페이지 렌더링
    return templates.TemplateResponse(
        request=request,
        name="/mst/notice_detail.html",  # 상세 보기 템플릿 이름 확인 필요
        context={"request": request, "notice": notice}
    )


# ==========================================
# 5. 게시글 삭제 처리 (POST) - 논리적 삭제(Soft Delete)
# ==========================================
@router.post("/notice/{notice_id}/delete")
async def delete_notice(
        request: Request,
        notice_id: int,
        password: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    stmt = select(Notice).filter(Notice.id == notice_id, Notice.attrib != 'XXXUPXXXUP')
    result = await db.execute(stmt)
    notice = result.scalar_one_or_none()

    if not notice:
        return HTMLResponse("<script>alert('존재하지 않는 게시글입니다.'); history.back();</script>")

    # 비밀번호 검증
    if notice.password != password:
        return HTMLResponse("<script>alert('비밀번호가 일치하지 않습니다.'); history.back();</script>")

    # ★ 실제 삭제(db.delete) 및 파일 삭제(os.remove)를 하지 않고 attrib만 변경
    notice.attrib = "XXXUPXXXUP"
    await db.commit()

    # 삭제 완료 후 목록으로 이동
    return HTMLResponse("<script>alert('성공적으로 삭제되었습니다.'); location.href='/notice';</script>")


# ==========================================
# 6. 게시글 수정 전 비밀번호 확인 및 폼 렌더링 (POST)
# ==========================================
@router.post("/notice/{notice_id}/edit_check")
async def edit_check_notice(
        request: Request,
        notice_id: int,
        password: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    # 삭제된 글은 수정 불가
    stmt = select(Notice).options(selectinload(Notice.files)).filter(
        Notice.id == notice_id,
        Notice.attrib != 'XXXUPXXXUP'
    )
    result = await db.execute(stmt)
    notice = result.scalar_one_or_none()

    if not notice:
        return HTMLResponse("<script>alert('존재하지 않는 게시글입니다.'); history.back();</script>")

    # 비밀번호 검증
    if notice.password != password:
        return HTMLResponse("<script>alert('비밀번호가 일치하지 않습니다.'); history.back();</script>")

    return templates.TemplateResponse(
        request=request,
        name="/mst/edit_notice.html",
        context={"request": request, "notice": notice}
    )


# ==========================================
# 7. 게시글 실제 수정 처리 (POST)
# ==========================================
@router.post("/notice/{notice_id}/edit")
async def update_notice(
        request: Request,
        notice_id: int,
        title: str = Form(...),
        author: str = Form(...),
        content: str = Form(...),
        password: str = Form(...),
        noticeCheck: Optional[str] = Form(None),
        files: List[UploadFile] = File(None),
        db: AsyncSession = Depends(get_db)
):
    # 삭제된 글은 수정 불가
    stmt = select(Notice).filter(Notice.id == notice_id, Notice.attrib != 'XXXUPXXXUP')
    result = await db.execute(stmt)
    notice = result.scalar_one_or_none()

    if not notice:
        return HTMLResponse("<script>alert('존재하지 않는 게시글입니다.'); history.back();</script>")

    if notice.password != password:
        return HTMLResponse("<script>alert('비밀번호가 일치하지 않습니다.'); history.back();</script>")

    notice.title = title
    notice.author = author
    notice.content = content
    notice.is_notice = 'Y' if noticeCheck == 'Y' else 'N'

    if files:
        for file in files:
            if file.filename == "":
                continue
            original_name = file.filename
            ext = os.path.splitext(original_name)[1]
            saved_name = f"{uuid.uuid4().hex}{ext}"
            file_path = os.path.join(UPLOAD_DIR, saved_name)

            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            file_size = os.path.getsize(file_path)
            new_file = NoticeFile(
                notice_id=notice.id,
                original_name=original_name,
                saved_name=saved_name,
                file_path=file_path,
                file_size=file_size
            )
            db.add(new_file)

    await db.commit()

    return RedirectResponse(url="/notice", status_code=303)
