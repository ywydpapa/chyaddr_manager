from sqlalchemy import Column, Integer, String, Text, Enum, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

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
