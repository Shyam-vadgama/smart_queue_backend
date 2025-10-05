from sqlalchemy import create_engine, Column, Integer, String, Enum, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from pydantic import BaseModel, constr, conint, validator
from typing import Optional

Base = declarative_base()

class Role(PyEnum):
    customer = 'customer'
    staff = 'staff'
    admin = 'admin'

class Status(PyEnum):
    waiting = 'waiting'
    in_service = 'in_service'
    completed = 'completed'
    cancelled = 'cancelled'

class User(Base):
    __tablename__ = 'Users'
    UserID = Column(Integer, primary_key=True, autoincrement=True)
    Username = Column(String(255), unique=True, nullable=False)
    Password = Column(String(255), nullable=False)
    Email = Column(String(255), unique=True, nullable=False)
    FirstName = Column(String(255))
    LastName = Column(String(255))
    Role = Column(Enum(Role), nullable=False)
    OrganizationID = Column(Integer, ForeignKey('Organizations.OrganizationID'))
    CreatedAt = Column(DateTime, server_default=func.now())
    UpdatedAt = Column(DateTime, server_default=func.now(), onupdate=func.now())

    organization = relationship("Organization", back_populates="users")
    queues = relationship("Queue", back_populates="customer")
    feedback = relationship("Feedback", back_populates="customer")

class Organization(Base):
    __tablename__ = 'Organizations'
    OrganizationID = Column(Integer, primary_key=True, autoincrement=True)
    OrganizationName = Column(String(255), unique=True, nullable=False)
    Description = Column(Text)
    CreatedAt = Column(DateTime, server_default=func.now())
    UpdatedAt = Column(DateTime, server_default=func.now(), onupdate=func.now())

    users = relationship("User", back_populates="organization")
    services = relationship("Service", back_populates="organization")

class Service(Base):
    __tablename__ = 'Services'
    ServiceID = Column(Integer, primary_key=True, autoincrement=True)
    ServiceName = Column(String(255), nullable=False)
    Description = Column(Text)
    OrganizationID = Column(Integer, ForeignKey('Organizations.OrganizationID'))
    CreatedAt = Column(DateTime, server_default=func.now())
    UpdatedAt = Column(DateTime, server_default=func.now(), onupdate=func.now())

    organization = relationship("Organization", back_populates="services")
    queues = relationship("Queue", back_populates="service")
    feedback = relationship("Feedback", back_populates="service")

class Queue(Base):
    __tablename__ = 'Queues'
    TokenID = Column(Integer, primary_key=True, autoincrement=True)
    CustomerID = Column(Integer, ForeignKey('Users.UserID'))
    ServiceID = Column(Integer, ForeignKey('Services.ServiceID'))
    TokenNumber = Column(Integer, nullable=False)
    Status = Column(Enum(Status), nullable=False)
    Priority = Column(Integer, default=0)
    CreatedAt = Column(DateTime, server_default=func.now())
    UpdatedAt = Column(DateTime, server_default=func.now(), onupdate=func.now())

    customer = relationship("User", back_populates="queues")
    service = relationship("Service", back_populates="queues")

class Feedback(Base):
    __tablename__ = 'Feedback'
    FeedbackID = Column(Integer, primary_key=True, autoincrement=True)
    CustomerID = Column(Integer, ForeignKey('Users.UserID'))
    ServiceID = Column(Integer, ForeignKey('Services.ServiceID'))
    Rating = Column(Integer)
    Comment = Column(Text)
    CreatedAt = Column(DateTime, server_default=func.now())

    customer = relationship("User", back_populates="feedback")
    service = relationship("Service", back_populates="feedback")

# Pydantic models for input validation
class UserCreate(BaseModel):
    username: constr(min_length=1, max_length=255)
    password: str
    email: constr(min_length=1, max_length=255)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str
    organization_id: int

    @validator('password')
    def password_length(cls, v):
        if len(v.encode('utf-8')) > 72:
            raise ValueError('Password must be at most 72 bytes long')
        return v

    @validator("role")
    def validate_role(cls, value):
        try:
            Role(value)
        except ValueError:
            raise ValueError("Invalid role")
        return value

class ServiceCreate(BaseModel):
    service_name: constr(min_length=1, max_length=255)
    description: Optional[str] = None
    organization_id: int

class ServiceUpdate(BaseModel):
    service_name: Optional[constr(min_length=1, max_length=255)] = None
    description: Optional[str] = None
    organization_id: Optional[int] = None

class EmployeeCreate(BaseModel):
    username: constr(min_length=1, max_length=255)
    password: str
    email: constr(min_length=1, max_length=255)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Role
    organization_id: int

    @validator('password')
    def password_length(cls, v):
        if len(v.encode('utf-8')) > 72:
            raise ValueError('Password must be at most 72 bytes long')
        return v

class EmployeeUpdate(BaseModel):
    username: Optional[constr(min_length=1, max_length=255)] = None
    password: Optional[str] = None
    email: Optional[constr(min_length=1, max_length=255)] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[Role] = None
    organization_id: Optional[int] = None

    @validator('password')
    def password_length(cls, v):
        if v and len(v.encode('utf-8')) > 72:
            raise ValueError('Password must be at most 72 bytes long')
        return v

class FeedbackCreate(BaseModel):
    customer_id: int
    service_id: int
    rating: conint(ge=1, le=5)
    comment: Optional[str] = None