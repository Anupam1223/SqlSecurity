from .database import Base
from sqlalchemy import Column, String, Boolean


class Login(Base):
    __tablename__ = "login"

    first_name = Column(String(20), primary_key=True, index=True)
    last_name = Column(String(20), nullable=False)
    username = Column(String(20), nullable=False)
    email = Column(String(20), nullable=False)
    password = Column(String(250), nullable=False)
    status = Column(Boolean, nullable=False)
