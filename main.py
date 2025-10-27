from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from typing import Optional
import logging, os, io, base64, asyncio, qrcode

from models import Base, User, Organization, Service, Queue, Feedback, Role as UserRole, Status
from schemas import (
    UserCreate, OrganizationCreate, ServiceCreate, FeedbackCreate, 
    ServiceUpdate
)

# --- CONFIG ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set in environment variables")

SECRET_KEY = "supersecretkeyhere"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- APP SETUP ---
app = FastAPI(title="Queue Management System", version="1.0.0")
logging.basicConfig(level=logging.INFO)

# --- DB SETUP ---
engine = create_engine(DATABASE_URL)
from sqlalchemy.orm import sessionmaker
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        default_org = db.query(Organization).filter(Organization.OrganizationID == 1).first()
        if not default_org:
            db.add(Organization(
                OrganizationName="Default Organization",
                Description="System Default Organization"
            ))
            db.commit()
            logging.info("Created Default Organization (ID=1)")
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- SECURITY ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_password_hash(password: str) -> str:
    """Hash password safely (bcrypt max 72 bytes limit)."""
    if len(password.encode('utf-8')) > 72:
        password = password[:72]
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    if len(plain.encode('utf-8')) > 72:
        plain = plain[:72]
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- AUTH HELPERS ---
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = db.query(User).filter(User.Username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(role: UserRole):
    """Role-based access dependency."""
    def wrapper(current_user: User = Depends(get_current_user)):
        if current_user.Role != role:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return current_user
    return wrapper

# --- ROUTES ---
@app.get("/")
async def root():
    return {"message": "Queue Management API running 🚀"}

# -------------------- AUTH --------------------
@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter((User.Username == user.username) | (User.Email == user.email)).first():
        raise HTTPException(status_code=400, detail="Username or Email already exists")

    org = db.query(Organization).filter(Organization.OrganizationID == user.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        role_enum = UserRole(user.role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")

    hashed_pwd = get_password_hash(user.password)
    new_user = User(
        Username=user.username,
        Password=hashed_pwd,
        Email=user.email,
        FirstName=user.first_name,
        LastName=user.last_name,
        Role=role_enum,
        OrganizationID=org.OrganizationID
    )
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.Username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.Password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.Username, "role": user.Role.value})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.UserID,
        "username": current_user.Username,
        "role": current_user.Role.value,
        "organization_id": current_user.OrganizationID
    }

# -------------------- ORGANIZATION --------------------
@app.post("/organizations")
def create_organization(org: OrganizationCreate, db: Session = Depends(get_db)):
    if db.query(Organization).filter(Organization.OrganizationName == org.name).first():
        raise HTTPException(status_code=400, detail="Organization already exists")
    new_org = Organization(OrganizationName=org.name, Description=org.description)
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    return {"id": new_org.OrganizationID, "name": new_org.OrganizationName}

# -------------------- SERVICE --------------------
@app.post("/admin/services", dependencies=[Depends(require_role(UserRole.admin))])
def create_service(service: ServiceCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if service.organization_id != current_user.OrganizationID:
        raise HTTPException(status_code=403, detail="Cannot create service for other organization")
    
    new_service = Service(
        ServiceName=service.service_name,
        Description=service.description,
        OrganizationID=service.organization_id
    )
    db.add(new_service)
    db.commit()
    db.refresh(new_service)
    return {"message": "Service created", "service_id": new_service.ServiceID}

@app.get("/services")
def list_services(db: Session = Depends(get_db)):
    services = db.query(Service).all()
    if not services:
        raise HTTPException(status_code=404, detail="No services found")
    return services

# -------------------- QR CODE --------------------
@app.get("/service/{service_id}/qr")
def generate_service_qr(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.ServiceID == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    qr_data = f"QUEUE_JOIN:{service.ServiceID}:{service.ServiceName}"
    qr = qrcode.make(qr_data)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return {
        "service_id": service.ServiceID,
        "service_name": service.ServiceName,
        "qr_image": f"data:image/png;base64,{qr_base64}"
    }

# -------------------- FEEDBACK --------------------
@app.post("/feedback")
def submit_feedback(feedback: FeedbackCreate, db: Session = Depends(get_db)):
    if not db.query(Service).filter(Service.ServiceID == feedback.service_id).first():
        raise HTTPException(status_code=404, detail="Service not found")

    fb = Feedback(
        CustomerID=feedback.customer_id,
        ServiceID=feedback.service_id,
        Rating=feedback.rating,
        Comment=feedback.comment
    )
    db.add(fb)
    db.commit()
    return {"message": "Feedback submitted successfully"}

