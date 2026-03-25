from pathlib import Path
import os
import dotenv
import jwt
from fastapi import (
    FastAPI,
    Depends,
    Request,
    Form,
    Response,
    HTTPException,
    Body,File, UploadFile
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from starlette.middleware.sessions import SessionMiddleware
import dotenv
from starlette.responses import JSONResponse

import funchub
from funchub import ALGORITHM, JWT_SECRET_KEY, get_password_hash, verify_password, get_current_user

dotenv.load_dotenv()

DATABASE_URL = os.getenv("dburl")
if not DATABASE_URL:
    raise RuntimeError("환경변수 dburl 이 설정되어 있지 않습니다.")

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_timeout=10,
    pool_recycle=1800,
)

async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecretkey"),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/thumbnails", StaticFiles(directory="static/img/members/"), name="thumbnails")

security = HTTPBearer()


async def get_db():
    async with async_session() as session:
        yield session


def _clean_str(value: object) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s != "" else None

def _clean_int(value: object) -> int | None:
    s = _clean_str(value)
    if s is None:
        return None
    try:
        return int(s)
    except ValueError:
        raise ValueError(f"Invalid integer input: {s!r}")

def to_int(s, default=0):
    try:
        return int(s)
    except Exception:
        return default


async def get_current_mobile_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        memberno = payload.get("sub")
        if memberno is None:
            raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")
        return memberno
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다. 다시 로그인해주세요.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="잘못된 토큰입니다.")


@app.get("/favicon.ico")
async def favicon():
    return {"detail": "Favicon is served at /static/favicon.ico"}


@app.get("/", response_class=HTMLResponse)
async def login_form(request: Request):
    if request.session.get("user_No"):
        return RedirectResponse(url="/success", status_code=303)
    return templates.TemplateResponse("login/login.html", {"request": request})


@app.post("/loginset")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    query = text(
        "SELECT userNo, userName, userRole, userPasswd "
        "FROM chyUser WHERE userId = :username"
    )
    result = await db.execute(query, {"username": username})
    user = result.fetchone()

    if not user:
        return templates.TemplateResponse(
            "login/login.html",
            {"request": request, "error": "Invalid credentials"},
        )

    user_no = user[0]
    user_name = user[1]
    user_role = user[2]
    stored_password = user[3] or ""

    authenticated = False
    try:
        authenticated = verify_password(password, stored_password)
    except Exception:
        authenticated = False
    if not authenticated and isinstance(stored_password, str) and stored_password.strip() == password:
        new_hashed_password = get_password_hash(password)
        update_sql = text("UPDATE chyUser SET userPasswd = :passwd WHERE userNo = :userno")
        await db.execute(update_sql, {"passwd": new_hashed_password, "userno": user_no})
        await db.commit()
        authenticated = True
    if not authenticated:
        return templates.TemplateResponse(
            "login/login.html",
            {"request": request, "error": "Invalid credentials"},
        )
    request.session["user_No"] = user_no
    request.session["user_Name"] = user_name
    request.session["user_Role"] = user_role
    request.session["user_Class"] = None
    return RedirectResponse(url="/success", status_code=303)


@app.post("/changeuserpass")
async def change_password(
    data: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    try:
        raw_password = data["passwd"]
        user_no = data["uno"]
    except KeyError:
        raise HTTPException(status_code=400, detail="passwd 또는 uno 값이 없습니다.")

    if not isinstance(raw_password, str) or not raw_password.strip():
        raise HTTPException(status_code=400, detail="비밀번호가 올바르지 않습니다.")

    hashed_password = get_password_hash(raw_password)
    sql = text("UPDATE chyUser SET userPasswd = :passwd WHERE userNo = :userno")
    await db.execute(sql, {"passwd": hashed_password, "userno": user_no})
    await db.commit()

    return {"result": "success"}


@app.get("/success", response_class=HTMLResponse)
async def success_page(request: Request):
    return templates.TemplateResponse("main/index.html", {"request": request})


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/rankList", response_class=HTMLResponse)
async def rankList(request: Request, db: AsyncSession = Depends(get_db)):
    rank_list = await funchub.get_ranklist(db)
    return templates.TemplateResponse("mst/mst_rank.html", {
        "request": request, "rank_list": rank_list })


@app.get("/memberList", response_class=HTMLResponse)
async def memberList(request: Request, db: AsyncSession = Depends(get_db)):
    member_list = await funchub.get_memberlist(db)
    return templates.TemplateResponse("mst/mst_member.html", {
        "request": request, "member_list": member_list })


@app.get("/categoryList", response_class=HTMLResponse)
async def categoryList(request: Request, db: AsyncSession = Depends(get_db)):
    category_list = await funchub.get_catgorylist(db)
    return templates.TemplateResponse("mst/mst_category.html", {
        "request": request, "category_list": category_list })


@app.get("/add_rank", response_class=HTMLResponse)
async def add_rank(request: Request, db: AsyncSession = Depends(get_db)):
    query = text(
        "INSERT INTO chyRank (rankTitlekor, rankTitleeng, rankType, sortNo) values (:rankTitlekor, :rankTitleeng, :rankType, :orderNo)")
    await db.execute(query,
                     {"rankTitlekor": "새로 등록된 직책", "rankTitleeng": "New Rank", "rankType": "CLASS", "orderNo": "0"})
    await db.commit()
    return RedirectResponse(f"/rankList", status_code=303)


@app.get("/add_category", response_class=HTMLResponse)
async def add_catgory(request: Request, db: AsyncSession = Depends(get_db)):
    query = text(
        "INSERT INTO chyCategory (catTitle, catTitleEng, catType, useYn) values (:catTitlekor, :catTitleeng, :catType, :useYn)")
    await db.execute(query,
                     {"catTitlekor": "새로 등록된 카테고리", "catTitleeng": "New Category", "catType": "MBIFO", "useYn": "Y"})
    await db.commit()
    return RedirectResponse(f"/categoryList", status_code=303)


@app.get("/add_member", response_class=HTMLResponse)
async def add_member(request: Request, db: AsyncSession = Depends(get_db)):
    query = text(
        "INSERT INTO chyMember (memberName, memberMF) values (:membername, :membermf)")
    await db.execute(query,
                     {"membername": "새로 등록된 회원", "membermf": "M"})
    await db.commit()
    return RedirectResponse(f"/memberList", status_code=303)


@app.get("/add_class", response_class=HTMLResponse)
async def add_class(request: Request, db: AsyncSession = Depends(get_db)):
    query = text(
        "INSERT INTO chyClass (classTitle) values (:classTitle)")
    await db.execute(query,
                     {"classTitle": "새로 등록된 기수"})
    await db.commit()
    return RedirectResponse(f"/classList", status_code=303)


@app.post("/update_rank/{rankno}", response_class=HTMLResponse)
async def update_rank(request: Request, rankno: int, db: AsyncSession = Depends(get_db)):
    form_data = await request.form()
    data4update = {
        "rankNo": rankno, "rankTitlekor": form_data.get("rankkor"), "rankTitleeng": form_data.get("rankeng"),
        "rankType": form_data.get("ranktype"), "sortNo": form_data.get("orderno"), "useYN": form_data.get("useyn"),}
    query = text("UPDATE chyRank SET rankTitlekor = :rankTitlekor, rankTitleeng = :rankTitleeng, rankType = :rankType, sortNo = :sortNo, useYN = :useYN WHERE rankNo = :rankNo")
    await db.execute(query, data4update)
    await db.commit()
    return RedirectResponse(f"/rankDetail/{rankno}?msg=success", status_code=303)


@app.post("/update_class/{classno}", response_class=HTMLResponse)
async def update_class(request: Request, classno: int, db: AsyncSession = Depends(get_db)):
    form_data = await request.form()
    data4update = {
        "classNo": classno, "classTitle": form_data.get("classtitle"), "classFrom": form_data.get("classfr"),
        "classTo": form_data.get("classto"),}
    query = text("UPDATE chyClass SET classTitle = :classTitle, classFrom = :classFrom, classTo = :classTo WHERE classNo = :classNo")
    await db.execute(query, data4update)
    await db.commit()
    return RedirectResponse(f"/classDetail/{classno}?msg=success", status_code=303)


@app.post("/update_category/{catno}", response_class=HTMLResponse)
async def update_category(request: Request, catno: int, db: AsyncSession = Depends(get_db)):
    form_data = await request.form()
    data4update = {
        "catNo": catno, "catTitle": form_data.get("cattitle"), "catTitleEng": form_data.get("cattitleeng"),
        "catType": form_data.get("cattype"), "useYN": form_data.get("useyn"),}
    query = text("UPDATE chyCategory SET catTitle = :catTitle, catTitleEng = :catTitleEng, catType = :catType, useYN = :useYN, modDate = NOW() WHERE catNo = :catNo")
    await db.execute(query, data4update)
    await db.commit()
    return RedirectResponse(f"/categoryDetail/{catno}?msg=success", status_code=303)


@app.get("/rankDetail/{rankno}", response_class=HTMLResponse)
async def rank_detail(request: Request, rankno: int, db: AsyncSession = Depends(get_db)):
    rank_detail = await funchub.get_rankdetail(db, rankno)
    return templates.TemplateResponse("mst/edit_rank.html", { "request": request, "rank_dtl": rank_detail })


@app.get("/classList", response_class=HTMLResponse)
async def classList(request: Request, db: AsyncSession = Depends(get_db)):
    class_list = await funchub.get_classlist(db)
    return templates.TemplateResponse("mst/mst_class.html", {
        "request": request, "class_list": class_list })


@app.get("/classDetail/{classno}", response_class=HTMLResponse)
async def rank_detail(request: Request, classno: int, db: AsyncSession = Depends(get_db)):
    class_detail = await funchub.get_classdetail(db, classno)
    return templates.TemplateResponse("mst/edit_class.html", { "request": request, "class_dtl": class_detail })


@app.get("/categoryDetail/{catno}", response_class=HTMLResponse)
async def category_detail(request: Request, catno: int, db: AsyncSession = Depends(get_db)):
    category_detail = await funchub.get_categorydetail(db, catno)
    return templates.TemplateResponse("mst/edit_category.html", { "request": request, "category_dtl": category_detail })


@app.get("/memberDetail/{memberno}", response_class=HTMLResponse)
async def member_detail(request: Request, memberno: int, db: AsyncSession = Depends(get_db)):
    member_detail = await funchub.get_memberdetail(db, memberno)
    categories = await funchub.get_categorybytype(db, 'MBIFO')
    return templates.TemplateResponse("mst/edit_member.html", { "request": request, "member_dtl": member_detail, "categories": categories })


@app.get("/api/member/{memberno}/midtl")
async def api_member_midt_list(memberno: int, request: Request, db: AsyncSession = Depends(get_db), user_no: int = Depends(get_current_user)):
    result = await db.execute(text("SELECT d.infoNo as id, d.catNo, c.catTitle, d.infoContents, DATE_FORMAT(d.regDate, '%Y-%m-%d') AS regDate FROM chyMemberInfo d JOIN chyCategory c ON c.catNo = d.catNo WHERE d.memberNo = :mno AND d.attrib = :xapp ORDER BY d.catNo ASC"), {"mno": memberno, "xapp": "1000010000"})
    return {"ok": True, "rows": [dict(r._mapping) for r in result.fetchall()]}


@app.post("/insert_MIDTL/{memberno}/")
async def insert_midt_detail(request: Request, memberno: int, db: AsyncSession = Depends(get_db)):
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if not request.session.get("user_No"):
        return JSONResponse({"ok": False, "message": "login required"}, status_code=401) if is_ajax else RedirectResponse(url="/", status_code=303)
    form = await request.form()
    cat_no, detail_info = to_int(form.get("dtlcat"), 0), (form.get("dtlcont") or "").strip()
    if cat_no <= 0 or detail_info == "":
        return JSONResponse({"ok": False, "message": "invalid input"}, status_code=400)
    try:
        async with db.begin():
            await db.execute(text("UPDATE chyMemberInfo SET attrib = :xup, modDate = NOW() WHERE memberNo = :mno AND catNo = :cno AND attrib = :xapp"), {"xup": "XXXUPXXXUP", "mno": memberno, "cno": cat_no, "xapp": "1000010000"})
            result = await db.execute(text("INSERT INTO chyMemberInfo (memberNo, catNo, infoContents, attrib, regDate) VALUES (:mno, :cno, :info, :xapp, NOW())"), {"mno": memberno, "cno": cat_no, "info": detail_info, "xapp": "1000010000"})
            row = (await db.execute(text("SELECT d.infoNo as id, d.memberNo, d.catNo, c.catTitle, d.infoContents, DATE_FORMAT(d.regDate, '%Y-%m-%d') AS regDate FROM chyMemberInfo d JOIN chyCategory c ON c.catNo = d.catNo WHERE d.infoNo = :id"), {"id": result.lastrowid})).mappings().first()
        return JSONResponse({"ok": True, "row": dict(row) if row else None}) if is_ajax else RedirectResponse(url=request.headers.get("referer", "/"), status_code=303)
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.post("/uploadcmphoto/{memberno}", dependencies=[Depends(get_current_user)])
async def upload_memberimage(request: Request, memberno: int, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    try:
        if not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File type not supported.")
        contents = await funchub.safe_file_read(file)
        contents = await funchub.resize_image_if_needed(contents, max_bytes=102400)
        await funchub.save_memberPhoto(contents, memberno)
        return RedirectResponse(f"/memberDetail/{memberno}", status_code=303)
    except Exception as e:
        print(f"Error: {e}")
        return RedirectResponse(f"/memberDetail/{memberno}", status_code=303)