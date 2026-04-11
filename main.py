from pathlib import Path
import os
from PIL import Image
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
from datetime import datetime, timedelta
import funchub
from funchub import ALGORITHM, JWT_SECRET_KEY, get_password_hash, verify_password, get_current_user
from typing import Optional

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
    return templates.TemplateResponse(request=request, name="login/login.html", context={"request": request})


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
            request=request, name="login/login.html",
            context={"request": request, "error": "Invalid credentials"},
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
            request=request, name="login/login.html",
            context={"request": request, "error": "Invalid credentials"},
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
    return templates.TemplateResponse(request=request, name="main/index.html", context={"request": request})


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/rankList", response_class=HTMLResponse)
async def rankList(request: Request, db: AsyncSession = Depends(get_db)):
    rank_list = await funchub.get_ranklist(db)
    return templates.TemplateResponse(request=request, name = "mst/mst_rank.html", context={
        "request": request, "rank_list": rank_list })


@app.get("/memberList", response_class=HTMLResponse)
async def memberList(request: Request, db: AsyncSession = Depends(get_db)):
    member_list = await funchub.get_memberlist(db)
    return templates.TemplateResponse(request=request, name="mst/mst_member.html", context={
        "request": request, "member_list": member_list })


@app.get("/categoryList", response_class=HTMLResponse)
async def categoryList(request: Request, db: AsyncSession = Depends(get_db)):
    category_list = await funchub.get_catgorylist(db)
    return templates.TemplateResponse(request=request, name="mst/mst_category.html", context={
        "request": request, "category_list": category_list })


@app.get("/add_rank", response_class=HTMLResponse)
async def add_rank(request: Request, db: AsyncSession = Depends(get_db)):
    query = text(
        "INSERT INTO chyRank (rankTitlekor, rankTitleeng, rankType, sortNo) values (:rankTitlekor, :rankTitleeng, :rankType, :orderNo)")
    await db.execute(query,
                     {"rankTitlekor": "새로 등록된 직책", "rankTitleeng": "New Rank", "rankType": "CLASS", "orderNo": "0"})
    await db.commit()
    return RedirectResponse(f"/rankList", status_code=303)


@app.get("/add_company", response_class=HTMLResponse)
async def add_company(request: Request, db: AsyncSession = Depends(get_db)):
    query = text(
        "INSERT INTO chyCompany (compName, compNameeng, compType, vatNo) values (:compname, :compnameeng, :comptype, :vatno)")
    await db.execute(query,
                     {"compname": "새로 등록된 거래처", "compnameeng": "New Company", "comptype": "TRADE", "vatno": "000-00-00000"})
    await db.commit()
    return RedirectResponse(f"/companyList", status_code=303)


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


@app.get("/add_event", response_class=HTMLResponse)
async def add_event(
        request: Request,
        start: Optional[str] = None,
        end: Optional[str] = None,
        db: AsyncSession = Depends(get_db)
):
    if start and end:
        start_time = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    else:
        now = datetime.now()
        start_time = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        end_time = start_time + timedelta(hours=3)
    query = text("""
                 INSERT INTO chyEvent (eventTitle, eventPlace, eventFrom, eventTo)
                 VALUES (:etitle, :eplace, :efrom, :eto)
                 """)
    await db.execute(query, {
        "etitle": "새로 등록된 Event",
        "eplace": "미정",
        "efrom": start_time,
        "eto": end_time
    })
    await db.commit()
    return RedirectResponse(url="/event_list", status_code=303)


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


@app.post("/update_comp/{compno}", response_class=HTMLResponse)
async def update_comp(request: Request, compno: int, db: AsyncSession = Depends(get_db)):
    form_data = await request.form()
    data4update = {
        "compNo": compno, "compName": form_data.get("compkor"),"compNameeng": form_data.get("compeng"), "vatNo": form_data.get("vatno"),
        "compType": form_data.get("comptype"),"useYn": form_data.get("useyn"), "bizType": form_data.get("biztype"),}
    query = text("UPDATE chyCompany SET compName = :compName, compNameeng = :compNameeng, vatNo = :vatNo, compType = :compType, useYn = :useYn, bizType = :bizType WHERE compNo = :compNo")
    await db.execute(query, data4update)
    await db.commit()
    return RedirectResponse(f"/companyDetail/{compno}?msg=success", status_code=303)


@app.post("/update_event/{eventno}", response_class=HTMLResponse)
async def update_event(request: Request, eventno: int, db: AsyncSession = Depends(get_db)):
    form_data = await request.form()
    data4update = {
        "eventNo": eventno, "eventTitle": form_data.get("eventtitle"), "eventFrom": form_data.get("eventfr"),
        "eventTo": form_data.get("eventto"),"eventPlace": form_data.get("eventplace"), }
    query = text("UPDATE chyEvent SET eventTitle = :eventTitle, eventFrom = :eventFrom, eventTo = :eventTo, eventPlace = :eventPlace WHERE eventNo = :eventNo")
    await db.execute(query, data4update)
    await db.commit()
    return RedirectResponse(f"/event_Detail/{eventno}?msg=success", status_code=303)


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
    return templates.TemplateResponse(request=request, name="mst/edit_rank.html", context={ "request": request, "rank_dtl": rank_detail })


@app.get("/classList", response_class=HTMLResponse)
async def classList(request: Request, db: AsyncSession = Depends(get_db)):
    class_list = await funchub.get_classlist(db)
    return templates.TemplateResponse(request=request, name="mst/mst_class.html", context={
        "request": request, "class_list": class_list })


@app.get("/companyList", response_class=HTMLResponse)
async def companyList(request: Request, db: AsyncSession = Depends(get_db)):
    comp_list = await funchub.get_companylist(db)
    return templates.TemplateResponse(request=request, name="mst/mst_company.html", context={
        "request": request, "comp_list": comp_list })


@app.get("/classDetail/{classno}", response_class=HTMLResponse)
async def rank_detail(request: Request, classno: int, db: AsyncSession = Depends(get_db)):
    class_detail = await funchub.get_classdetail(db, classno)
    return templates.TemplateResponse(request=request, name="mst/edit_class.html", context={ "request": request, "class_dtl": class_detail })


@app.get("/class_Detail/{classno}", response_class=HTMLResponse)
async def rank_detail(request: Request, classno: int, db: AsyncSession = Depends(get_db)):
    class_detail = await funchub.get_classdetail(db, classno)
    return templates.TemplateResponse(request=request, name="class/class_detail.html", context={ "request": request, "class_dtl": class_detail })


@app.get("/event_Detail/{eventno}", response_class=HTMLResponse)
async def event_detail(request: Request, eventno: int, db: AsyncSession = Depends(get_db)):
    event_detail = await funchub.get_eventdetail(db, eventno)
    return templates.TemplateResponse(request=request, name="class/event_detail.html", context={ "request": request, "event_dtl": event_detail })


@app.get("/categoryDetail/{catno}", response_class=HTMLResponse)
async def category_detail(request: Request, catno: int, db: AsyncSession = Depends(get_db)):
    category_detail = await funchub.get_categorydetail(db, catno)
    return templates.TemplateResponse(request=request, name="mst/edit_category.html", context={ "request": request, "category_dtl": category_detail })


@app.get("/companyDetail/{compno}", response_class=HTMLResponse)
async def company_detail(request: Request, compno: int, db: AsyncSession = Depends(get_db)):
    comp_detail = await funchub.get_companydetail(db, compno)
    return templates.TemplateResponse(request=request, name="mst/edit_company.html", context={ "request": request, "comp_dtl": comp_detail })


@app.get("/memberDetail/{memberno}", response_class=HTMLResponse)
async def member_detail(request: Request, memberno: int, db: AsyncSession = Depends(get_db)):
    member_detail = await funchub.get_memberdetail(db, memberno)
    category1 = await funchub.get_categorybytype(db, 'MBIFO')
    category2 = await funchub.get_categorybytype(db, 'MPRIZ')
    category3 = await funchub.get_categorybytype(db, 'MBCNC')
    return templates.TemplateResponse(request=request, name="mst/edit_member.html", context={ "request": request, "member_dtl": member_detail, "category1": category1, "category2": category2, "category3": category3 })


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


@app.post("/update_member/{memberno}", response_class=HTMLResponse)
async def updatemember(request: Request, memberno: int, db: AsyncSession = Depends(get_db), user_no: int = Depends(get_current_user)):
    form_data = await request.form()
    data = {"memberName": _clean_str(form_data.get("membername")), "memberNameEng": _clean_str(form_data.get("membernameeng")), "memberNameCn": _clean_str(form_data.get("membernamecn")), "memberMF": _clean_str(form_data.get("membermf")), "memberId": _clean_str(form_data.get("memberid")), "activeYN": _clean_str(form_data.get("memberstat")), "memberNo": memberno, "memberMemo": form_data.get("membermemo", '')}
    update_fields = {k: v for k, v in data.items() if v is not None}
    if update_fields:
        params = dict(update_fields)
        params["memberNo"] = memberno
        await db.execute(text(f"UPDATE chyMember SET {', '.join([f'{k} = :{k}' for k in update_fields.keys()])} WHERE memberNo = :memberNo"), params)
        await db.commit()
    return RedirectResponse(f"/memberDetail/{memberno}", status_code=303)


@app.get("/class_list", response_class=HTMLResponse)
async def classlists(request: Request, db: AsyncSession = Depends(get_db)):
    class_list = await funchub.get_classlist(db)
    return templates.TemplateResponse(request=request, name="class/class_list.html", context={
        "request": request, "class_list": class_list})


@app.get("/event_list", response_class=HTMLResponse)
async def eventlists(request: Request, db: AsyncSession = Depends(get_db)):
    event_list = await funchub.get_eventlist(db)
    return templates.TemplateResponse(request=request, name="class/event_list.html", context={
        "request": request, "event_list": event_list})


@app.get("/class_members/{classno}", response_class=HTMLResponse)
async def classmembers(request: Request,classno:int ,db: AsyncSession = Depends(get_db)):
    member_list = await funchub.get_memberlist(db)
    cmember_list = await funchub.get_classmemberlist(db, classno)
    ranks = await funchub.get_ranklist(db)
    return templates.TemplateResponse(request=request, name="class/class_members.html", context={
        "request": request, "member_list": member_list, "classno": classno, "cmember_list": cmember_list, "ranks": ranks})


@app.post("/membertoclass/{classno}/{memberno}")
async def membertoclass(request: Request, classno: int, memberno: int, db: AsyncSession = Depends(get_db)):
    query = text(f"select * from chyClassmember where classNo = :classno and memberNo = :memberno")
    result = await db.execute(query, {"classno": classno, "memberno": memberno})
    if result.rowcount == 0:
        query = text(f"INSERT into chyClassmember (classNo, memberNo) values (:classno, :memberno)")
        await db.execute(query, {"classno": classno, "memberno": memberno})
        await db.commit()
        return JSONResponse({"result": "ok"})
    else:
        return JSONResponse({"result": "already"})


@app.post("/membertoclassminus/{classno}/{memberno}")
async def membertoclassminus(request: Request, classno: int, memberno: int, db: AsyncSession = Depends(get_db)):
    query = text(f"select * from chyClassmember where classNo = :classno and memberNo = :memberno")
    result = await db.execute(query, {"classno": classno, "memberno": memberno})
    if result.rowcount != 0:
        query = text(f"DELETE FROM chyClassmember where classNo = :classno and memberNo = :memberno")
        await db.execute(query, {"classno": classno, "memberno": memberno})
        await db.commit()
        return JSONResponse({"result": "ok"})
    else:
        return JSONResponse({"result": "already"})


@app.get("/getclassmembers/{classno}", response_class=JSONResponse)
async def getclassmembers(request: Request, classno: int, db: AsyncSession = Depends(get_db)):
    rows = await funchub.get_classmemberlist(db, classno)
    members = [funchub.row_to_dict(row) for row in rows]
    return JSONResponse({"members": members})


@app.get("/event_members/{eventno}", response_class=HTMLResponse)
async def classmembers(request: Request,eventno:int ,db: AsyncSession = Depends(get_db)):
    member_list = await funchub.get_memberlist(db)
    cmember_list = await funchub.get_eventmemberlist(db, eventno)
    ranks = await funchub.get_ranklist(db)
    return templates.TemplateResponse(request=request, name="class/event_members.html", context={
        "request": request, "member_list": member_list, "classno": eventno, "cmember_list": cmember_list, "eventno": eventno, "ranks": ranks})


@app.post("/membertoevent/{eventno}/{memberno}")
async def membertoevent(request: Request, eventno: int, memberno: int, db: AsyncSession = Depends(get_db)):
    query = text(f"select * from chyEventmember where eventNo = :eventno and memberNo = :memberno")
    result = await db.execute(query, {"eventno": eventno, "memberno": memberno})
    query2 = text(f"select classRank from chyClassmember where memberNo = :memberno")
    result2 = await db.execute(query2, {"memberno": memberno})
    rank = result2.fetchone()
    if rank is None:
        rank = 5
    if result.rowcount == 0:
        query = text(f"INSERT into chyEventmember (eventNo, memberNo, classRank) values (:eventno, :memberno, :rank)")
        await db.execute(query, {"eventno": eventno, "memberno": memberno, "rank": rank[0]})
        await db.commit()
        return JSONResponse({"result": "ok"})
    else:
        return JSONResponse({"result": "already"})


@app.post("/membertoeventminus/{eventno}/{memberno}")
async def membertoeventminus(request: Request, eventno: int, memberno: int, db: AsyncSession = Depends(get_db)):
    query = text(f"select * from chyEventmember where eventNo = :eventno and memberNo = :memberno")
    result = await db.execute(query, {"eventno": eventno, "memberno": memberno})
    if result.rowcount != 0:
        query = text(f"DELETE FROM chyEventmember where eventNo = :eventno and memberNo = :memberno")
        await db.execute(query, {"eventno": eventno, "memberno": memberno})
        await db.commit()
        return JSONResponse({"result": "ok"})
    else:
        return JSONResponse({"result": "already"})


@app.get("/geteventmembers/{eventno}", response_class=JSONResponse)
async def geteventmembers(request: Request, eventno: int, db: AsyncSession = Depends(get_db)):
    rows = await funchub.get_eventmemberlist(db, eventno)
    members = [funchub.row_to_dict(row) for row in rows]
    return JSONResponse({"members": members})


@app.get("/event_notice/{eventno}", response_class=JSONResponse)
async def eventnotice(request: Request, eventno: int, db: AsyncSession = Depends(get_db)):
    rows = await funchub.get_eventmemberlist(db, eventno)
    return templates.TemplateResponse(request=request, name="class/event_offcialdoc.html", context={"request": request, "eventno": eventno, "members": rows})



@app.get("/api/member/{memberno}/prize")
async def api_member_prize_list(memberno: int, request: Request, db: AsyncSession = Depends(get_db),
                                user_no: int = Depends(get_current_user)):
    query = """
            SELECT p.mpNo                               as id, \
                   p.prizeNo, \
                   c.catTitle                           as prizeTitle,
                   DATE_FORMAT(p.prizeDate, '%Y-%m-%d') AS prizeDate,
                   p.eventNo,
                   p.prizeMemo
            FROM chyMemberprize p
                     JOIN chyCategory c ON c.catNo = p.prizeNo
            WHERE p.memberNo = :mno \
              AND p.attrib = :xapp
            ORDER BY p.prizeDate DESC, p.prizeNo ASC \
            """
    result = await db.execute(text(query), {"mno": memberno, "xapp": "1000010000"})
    return {"ok": True, "rows": [dict(r._mapping) for r in result.fetchall()]}

@app.post("/insert_PRIZE/{memberno}/")
async def insert_prize_detail(request: Request, memberno: int, db: AsyncSession = Depends(get_db)):
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if not request.session.get("user_No"):
        return JSONResponse({"ok": False, "message": "login required"},
                            status_code=401) if is_ajax else RedirectResponse(url="/", status_code=303)
    form = await request.form()
    prize_no = to_int(form.get("prizecat"), 0)
    prize_date = form.get("prizedate")
    prize_memo = (form.get("prizecont") or "").strip()
    event_no = to_int(form.get("eventno"), 0)  # eventNo가 숫자형(INT)이라고 가정

    if prize_no <= 0 or prize_memo == "":
        return JSONResponse({"ok": False, "message": "invalid input"}, status_code=400)

    try:
        async with db.begin():
            insert_query = """
                           INSERT INTO chyMemberprize (memberNo, prizeNo, prizeDate, prizeMemo, eventNo, attrib, regDate)
                           VALUES (:mno, :pno, :pdate, :pmemo, :eno, :xapp, NOW()) \
                           """
            result = await db.execute(text(insert_query), {
                "mno": memberno, "pno": prize_no, "pdate": prize_date, "pmemo": prize_memo, "eno": event_no,
                "xapp": "1000010000"
            })
            select_query = """
                           SELECT p.mpNo                               as id, \
                                  p.memberNo, \
                                  p.prizeNo, \
                                  c.catTitle                           as prizeTitle,
                                  DATE_FORMAT(p.prizeDate, '%Y-%m-%d') AS prizeDate,
                                  p.eventNo,
                                  p.prizeMemo
                           FROM chyMemberprize p
                                    JOIN chyCategory c ON c.catNo = p.prizeNo
                           WHERE p.mpNo = :id \
                           """
            row = (await db.execute(text(select_query), {"id": result.lastrowid})).mappings().first()
        return JSONResponse({"ok": True, "row": dict(row) if row else None}) if is_ajax else RedirectResponse(
            url=request.headers.get("referer", "/"), status_code=303)
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)

@app.get("/api/ephoto/events")
async def get_ephoto_events(db: AsyncSession = Depends(get_db)):
    photo_dir = Path("static/img/event")
    if not photo_dir.exists():
        return JSONResponse([])
    event_nos = set()
    for file in photo_dir.iterdir():
        if file.is_file() and "-" in file.name:
            try:
                event_no = int(file.name.split("-")[0])
                event_nos.add(event_no)
            except ValueError:
                continue
    if not event_nos:
        return JSONResponse([])
    query = text("""
                 SELECT a.eventNo, eventFrom , a.eventTitle ,a.eventPlace
                 FROM chyEvent a
                 WHERE a.eventNo IN :event_nos
                 ORDER BY a.eventFrom DESC
                 """)
    result = await db.execute(query, {"event_nos": tuple(event_nos)})
    rows = result.fetchall()
    events = []
    for row in rows:
        dt = row[1]
        dt_str = dt.strftime("%Y-%m-%d") if hasattr(dt, "strftime") else str(dt)
        name = row[2] or "알 수 없음"
        events.append({
            "eventNo": row[0],
            "label": f"[{dt_str}] {name} (행사번호: {row[0]}), (행사장소: {row[3]})",
        })
    return JSONResponse(events)


@app.get("/photo_album", response_class=HTMLResponse)
async def photoalbum(request: Request,db: AsyncSession = Depends(get_db)):
    return templates.TemplateResponse(request=request, name="event/manage_photo.html", context={
        "request": request})


@app.get("/photo_upload", response_class=HTMLResponse)
async def photoupload(request: Request,db: AsyncSession = Depends(get_db)):
    return templates.TemplateResponse(request=request, name="event/upload_photo.html", context={
        "request": request})


@app.get("/api/ephoto/photos/{event_no}")
async def get_ephoto_photos(event_no: int):
    photo_dir = Path("static/img/event")
    if not photo_dir.exists():
        return JSONResponse([])

    photos = []
    for file in photo_dir.glob(f"{event_no}-*.*"):
        if file.suffix.lower() in [".jpg", ".jpeg", ".png", ".webp"]:
            photos.append({
                "filename": file.name,
                "url": f"/static/img/event/{file.name}"
            })
    photos.sort(key=lambda x: x["filename"])
    return JSONResponse(photos)


@app.post("/api/ephoto/photos/{filename}/rotate")
async def rotate_ephoto(filename: str):
    file_path = Path("static/img/event") / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        with Image.open(file_path) as img:
            rotated = img.transpose(Image.ROTATE_270)
            rotated.save(file_path)

        import time
        return JSONResponse({
            "success": True,
            "url": f"/static/img/event/{filename}?t={int(time.time())}"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/ephoto/photos/{filename}")
async def delete_ephoto(filename: str):
    file_path = Path("static/img/event") / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        file_path.unlink()
        return JSONResponse({"success": True})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/get_event")
async def get_event(db: AsyncSession = Depends(get_db)):
    try:
        rows = await funchub.get_eventlist(db)
        result = [{"eventNo": row[0], "eventFrom": row[5], "eventTitle": row[1]} for row in rows]
    except Exception as e:
        result = []
    return {"events": result}


@app.post("/update_classmember_info")
async def update_classmember_info(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        form_data = await request.form()
        classno = form_data.get("classNo")
        memberno = form_data.get("memberNo")
        data = {
            "classRank": form_data.get("classRank"),
            "memberMemo": form_data.get("memberMemo", '')
        }
        update_fields = {k: v for k, v in data.items() if v is not None}

        if update_fields and classno and memberno:
            params = dict(update_fields)
            params["memberNo"] = memberno
            params["classNo"] = classno
            set_clause = ', '.join([f'{k} = :{k}' for k in update_fields.keys()])
            query = f"UPDATE chyClassmember SET {set_clause} WHERE memberNo = :memberNo AND classNo = :classNo"
            await db.execute(text(query), params)
            await db.commit()
        return {"result": "ok"}
    except Exception as e:
        print(f"Update Error: {e}")
        await db.rollback()
        return {"result": "error"}


@app.get("/print_document/{eventno}")
async def print_documents(
        request: Request,
        eventno: int,
        memberNo: Optional[str] = "all",
        customTitle: Optional[str] = None,
        db: AsyncSession = Depends(get_db)
):
    # 1. DB에서 데이터 가져오기 (SQLAlchemy Row 객체 리스트)
    raw_rows = await funchub.get_eventmemberlist(db, eventno)

    # 2. Row 객체는 수정이 불가능하므로, 모두 딕셔너리(dict)로 변환합니다.
    # (SQLAlchemy 1.4/2.0 방식: row._mapping 사용)
    rows = [dict(row._mapping) for row in raw_rows]

    if memberNo != "all":
        # 3. 딕셔너리로 변환되었으므로 ["memberNo"]로 안전하게 접근 및 필터링 가능
        filtered_rows = [row for row in rows if str(row["memberNo"]) == str(memberNo)]

        # 4. 프런트엔드에서 수정한 직책(customTitle)이 넘어왔다면 덮어쓰기
        if customTitle and filtered_rows:
            filtered_rows[0]["rankTitlekor"] = customTitle

        rows = filtered_rows

    return templates.TemplateResponse(
        name="templ/offdoc001.html",
        context={"request": request, "eventno": eventno, "members": rows}
    )


@app.post("/update_eventmember_info")
async def update_eventmember_info(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        form_data = await request.form()
        eventno = form_data.get("eventNo")
        memberno = form_data.get("memberNo")
        data = {
            "classRank": form_data.get("eventRank"),
            "memberMemo": form_data.get("memberMemo", '')
        }
        update_fields = {k: v for k, v in data.items() if v is not None}

        if update_fields and eventno and memberno:
            params = dict(update_fields)
            params["memberNo"] = memberno
            params["eventNo"] = eventno
            set_clause = ', '.join([f'{k} = :{k}' for k in update_fields.keys()])
            query = f"UPDATE chyEventmember SET {set_clause} WHERE memberNo = :memberNo AND eventNo = :eventNo"
            await db.execute(text(query), params)
            await db.commit()
        return {"result": "ok"}
    except Exception as e:
        print(f"Update Event Member Error: {e}")
        await db.rollback()
        return {"result": "error"}