from sqlalchemy import Column, Integer, String, Text, Enum, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
from sqlalchemy.dialects.mysql import LONGTEXT

# 1. 게시글 메인 모델
class Notice(Base):
    __tablename__ = "addrNotice"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    is_notice = Column(Enum('Y', 'N'), default='N')
    title = Column(String(255), nullable=False)
    author = Column(String(50), nullable=False)
    password = Column(String(100), nullable=True)
    content = Column(Text, nullable=False)
    view_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    attrib = Column(String(10), default='1000010000')

    # 첨부파일 테이블과의 관계 설정 (게시글 삭제 시 파일 정보도 삭제되도록 cascade 설정)
    files = relationship("NoticeFile", back_populates="notice", cascade="all, delete-orphan")

# 2. 첨부파일 모델
class NoticeFile(Base):
    __tablename__ = "addrNotice_files"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    notice_id = Column(Integer, ForeignKey("addrNotice.id", ondelete="CASCADE"), nullable=False)
    original_name = Column(String(255), nullable=False)
    saved_name = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())

    # 게시글 테이블과의 관계 설정
    notice = relationship("Notice", back_populates="files")


class ChyTemplate(Base):
    __tablename__ = "chyTemplates"

    tempNo = Column(Integer, primary_key=True, autoincrement=True, comment="템플릿번호")
    tempType = Column(String(5), nullable=True, comment="템플릿타입")
    tempTitle = Column(String(1000), nullable=True, comment="템플릿제목")

    # MySQL의 longtext 타입을 정확히 반영하기 위해 LONGTEXT 사용
    # (만약 다른 DB와 호환성을 유지하려면 Text를 사용하셔도 됩니다.)
    tempContents = Column(LONGTEXT, nullable=True, comment="템플릿내용")

    tempBg = Column(String(100), nullable=True, comment="템플릿배경")
    tempFr = Column(String(100), nullable=True, comment="템플릿프레임")

    # default=func.now() 를 통해 INSERT 시 자동 시간 기록
    regDate = Column(DateTime, default=func.now(), comment="등록일")

    # onupdate=func.now() 를 통해 UPDATE 시 자동 시간 기록
    modDate = Column(DateTime, nullable=True, onupdate=func.now(), comment="수정일")

    attrib = Column(String(10), default="1000010000", comment="속성")
