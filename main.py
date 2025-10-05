from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
# Importing only the necessary SQLAlchemy models and enums from the local package
from .models import Base, User, Organization, Service, Queue, Feedback, Role as UserRole
from pydantic import BaseModel, constr, conint, validator
from typing import Optional
import asyncio
from fastapi import Form
from enum import Enum as PyEnum
import logging

# Set up logging for better debugging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# --- CONFIGURATION ---
# IMPORTANT: Replace these connection details with your actual PostgreSQL credentials.
# Format: postgresql+psycopg2://user:password@host:port/dbname
DATABASE_URL = "postgresql+psycopg2://postgres:admin@localhost:5432/smart_queue"
SECRET_KEY = "$2a$12$2DB3EJ9Eulsdg6i8kiohl.al3rlBNjWXCgghVBKt.cvJmCFCpuNhG"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
RATE_LIMIT = "100/minute"

# --- PYDANTIC SCHEMAS (Input Validation) ---

# Define the Pydantic models in main.py to avoid circular imports.
# Role is imported from models.py, but the schemas themselves live here.
class UserCreate(BaseModel):
    username: constr(min_length=1, max_length=255)
    password: constr(min_length=1)  # Ensure password is not empty
    email: constr(min_length=1, max_length=255)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str
    organization_id: int

    @validator("role")
    def validate_role(cls, value):
        try:
            UserRole(value)
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
    # Role uses the imported SQLAlchemy Enum type directly
    username: constr(min_length=1, max_length=255)
    password: constr(min_length=1)  # Ensure password is not empty
    email: constr(min_length=1, max_length=255)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: UserRole # Use the imported Role enum here
    organization_id: int

class EmployeeUpdate(BaseModel):
    username: Optional[constr(min_length=1, max_length=255)] = None
    password: Optional[constr(min_length=1)] = None  # Ensure password is not empty if provided
    email: Optional[constr(min_length=1, max_length=255)] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[UserRole] = None
    organization_id: Optional[int] = None

class FeedbackCreate(BaseModel):
    customer_id: int
    service_id: int
    rating: conint(ge=1, le=5)
    comment: Optional[str] = None

# --- AUTH & DB SETUP ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Setup SQLAlchemy Engine and Session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables in the database (only runs if tables don't exist)
Base.metadata.create_all(bind=engine)

# Create a default organization if it doesn't exist
def create_default_organization():
    db = SessionLocal()
    try:
        # Check if default organization exists
        default_org = db.query(Organization).filter(Organization.OrganizationID == 1).first()
        if not default_org:
            # Create default organization
            default_org = Organization(
                OrganizationName="Default Organization",
                Description="Default organization for the system"
            )
            db.add(default_org)
            db.commit()
            db.refresh(default_org)
            print("Created default organization with ID 1")
    finally:
        db.close()

# Create default organization on startup
create_default_organization()

app = FastAPI()
queue_lock = asyncio.Lock()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- SECURITY FUNCTIONS ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    """
    Hashes a password, truncating it to 72 bytes if necessary.
    This fixes the `ValueError: password cannot be longer than 72 bytes` error.
    """
    # Truncate to 72 bytes for bcrypt compatibility
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        # Truncate and decode back to string
        password_bytes = password_bytes[:72]
        password = password_bytes.decode('utf-8', errors='ignore')
    
    # Pass the string to passlib.hash for proper encoding/hashing
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = {"username": username}
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.Username == token_data["username"]).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def has_role(role: UserRole):
    def dependency(current_user: User = Depends(get_current_active_user)):
        # Role comparison is done against the SQLAlchemy Enum value
        if current_user.Role != role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
        return current_user
    return dependency

# --- MIDDLEWARE ---

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """
    Middleware to implement API rate limiting.
    """
    # TODO: Implement rate limiting logic (e.g., using a Redis counter)
    response = await call_next(request)
    return response

# --- ENDPOINTS ---

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Endpoint for registering a new user.
    """
    # Check if organization exists, if not use default organization (ID 1)
    organization = db.query(Organization).filter(Organization.OrganizationID == user.organization_id).first()
    if not organization:
        # Use default organization
        default_org = db.query(Organization).filter(Organization.OrganizationID == 1).first()
        if not default_org:
            raise HTTPException(status_code=500, detail="Default organization not found")
        organization_id = default_org.OrganizationID
    else:
        organization_id = user.organization_id
    
    existing_user = db.query(User).filter((User.Username == user.username) | (User.Email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Hash the password
    hashed_password = get_password_hash(user.password)

    try:
        # Convert Pydantic string role to SQLAlchemy Enum Role
        role_enum = UserRole(user.role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")

    new_user = User(
        Username=user.username, 
        Password=hashed_password, 
        Email=user.email, 
        FirstName=user.first_name, 
        LastName=user.last_name, 
        Role=role_enum, 
        OrganizationID=organization_id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}

@app.post("/token", response_model=None)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.Username == form_data.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    # Handle password verification by truncating the input password if necessary
    # This ensures consistency with how the password was hashed in get_password_hash
    password_to_verify = form_data.password
    password_bytes = password_to_verify.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
        password_to_verify = password_bytes.decode('utf-8', errors='ignore')

    if not verify_password(password_to_verify, user.Password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.Username, "role": user.Role.value}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=None)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/users/me/items/", response_model=None)
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.Username}]

@app.post("/customer/join_queue/{service_id}")
async def join_queue(service_id: int, customer_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for a customer to join a queue for a specific service.
    """
    service = db.query(Service).filter(Service.ServiceID == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    customer = db.query(User).filter(User.UserID == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    last_token = db.query(Queue).filter(Queue.ServiceID == service_id).order_by(Queue.TokenNumber.desc()).first()
    token_number = last_token.TokenNumber + 1 if last_token else 1

    new_token = Queue(CustomerID=customer_id, ServiceID=service_id, TokenNumber=token_number, Status="waiting")
    db.add(new_token)
    db.commit()
    db.refresh(new_token)

    return {"message": "Joined queue successfully", "token_number": new_token.TokenNumber}

@app.post("/customer/feedback", dependencies=[Depends(get_current_active_user)])
async def submit_feedback(feedback: FeedbackCreate, db: Session = Depends(get_db)):
    """
    Endpoint for a customer to submit feedback for a specific service.
    """
    service = db.query(Service).filter(Service.ServiceID == feedback.service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    customer = db.query(User).filter(User.UserID == feedback.customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    new_feedback = Feedback(CustomerID=feedback.customer_id, ServiceID=feedback.service_id, Rating=feedback.rating, Comment=feedback.comment)
    db.add(new_feedback)
    db.commit()
    db.refresh(new_feedback)

    return {"message": "Feedback submitted successfully"}

@app.post("/staff/token/call_next/{service_id}", dependencies=[Depends(has_role(UserRole.staff))])
async def call_next_token(service_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for staff to call the next waiting token for a specific service.
    """
    service = db.query(Service).filter(Service.ServiceID == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    # Get the next waiting token with the highest priority
    next_token = db.query(Queue).filter(Queue.ServiceID == service_id, Queue.Status == "waiting").order_by(Queue.Priority.desc(), Queue.TokenNumber.asc()).first()
    if not next_token:
        raise HTTPException(status_code=404, detail="No waiting tokens found")

    next_token.Status = "in_service"
    db.commit()
    db.refresh(next_token)

    customer = db.query(User).filter(User.UserID == next_token.CustomerID).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    return {"message": "Calling next token", "token_number": next_token.TokenNumber, "customer_id": customer.UserID, "customer_name": f"{customer.FirstName} {customer.LastName}"}

@app.post("/staff/token/complete/{token_id}", dependencies=[Depends(has_role(UserRole.staff))])
async def complete_token(token_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for staff to mark a token as completed.
    """
    token = db.query(Queue).filter(Queue.TokenID == token_id).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    token.Status = "completed"
    db.commit()
    db.refresh(token)

    return {"message": "Token completed successfully"}

@app.post("/staff/token/priority/{token_id}", dependencies=[Depends(has_role(UserRole.staff))])
async def set_token_priority(token_id: int, priority: int, db: Session = Depends(get_db)):
    """
    Endpoint for staff to set the priority of a token.
    """
    token = db.query(Queue).filter(Queue.TokenID == token_id).first()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    token.Priority = priority
    db.commit()
    db.refresh(token)

    return {"message": "Token priority updated successfully"}

@app.get("/admin/analytics", dependencies=[Depends(has_role(UserRole.admin))])
async def get_analytics(db: Session = Depends(get_db)):
    """
    Endpoint for admin to get analytics about the queue system.
    """
    # TODO: Implement analytics logic
    return {"message": "Analytics endpoint is not yet implemented."}

@app.post("/admin/service/create", dependencies=[Depends(has_role(UserRole.admin))])
async def create_service(service: ServiceCreate, db: Session = Depends(get_db)):
    """
    Endpoint for admin to create a new service.
    """
    organization = db.query(Organization).filter(Organization.OrganizationID == service.organization_id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    new_service = Service(ServiceName=service.service_name, Description=service.description, OrganizationID=service.organization_id)
    db.add(new_service)
    db.commit()
    db.refresh(new_service)

    return {"message": "Service created successfully"}

@app.put("/admin/service/update/{service_id}", dependencies=[Depends(has_role(UserRole.admin))])
async def update_service(service_id: int, service: ServiceUpdate, db: Session = Depends(get_db)):
    """
    Endpoint for admin to update an existing service.
    """
    service_obj = db.query(Service).filter(Service.ServiceID == service_id).first()
    if not service_obj:
        raise HTTPException(status_code=404, detail="Service not found")

    if service.organization_id:
        organization = db.query(Organization).filter(Organization.OrganizationID == service.organization_id).first()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        service_obj.OrganizationID = service.organization_id

    if service.service_name:
        service_obj.ServiceName = service.service_name
    if service.description:
        service_obj.Description = service.description
    db.commit()
    db.refresh(service_obj)

    return {"message": "Service updated successfully"}

@app.delete("/admin/service/delete/{service_id}", dependencies=[Depends(has_role(UserRole.admin))])
async def delete_service(service_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for admin to delete an existing service.
    """
    service = db.query(Service).filter(Service.ServiceID == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    db.delete(service)
    db.commit()

    return {"message": "Service deleted successfully"}

@app.post("/admin/employee/create", dependencies=[Depends(has_role(UserRole.admin))])
async def create_employee(employee: EmployeeCreate, db: Session = Depends(get_db)):
    """
    Endpoint for admin to create a new employee.
    """
    # Check if organization exists, if not use default organization (ID 1)
    organization = db.query(Organization).filter(Organization.OrganizationID == employee.organization_id).first()
    if not organization:
        # Use default organization
        default_org = db.query(Organization).filter(Organization.OrganizationID == 1).first()
        if not default_org:
            raise HTTPException(status_code=500, detail="Default organization not found")
        organization_id = default_org.OrganizationID
    else:
        organization_id = employee.organization_id

    existing_user = db.query(User).filter((User.Username == employee.username) | (User.Email == employee.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed_password = get_password_hash(employee.password)

    # Role is already validated by Pydantic model EmployeeCreate
    new_employee = User(
        Username=employee.username, 
        Password=hashed_password, 
        Email=employee.email, 
        FirstName=employee.first_name, 
        LastName=employee.last_name, 
        Role=employee.role, 
        OrganizationID=organization_id
    )
    db.add(new_employee)
    db.commit()
    db.refresh(new_employee)

    return {"message": "Employee created successfully"}

@app.put("/admin/employee/update/{employee_id}", dependencies=[Depends(has_role(UserRole.admin))])
async def update_employee(employee_id: int, employee: EmployeeUpdate, db: Session = Depends(get_db)):
    """
    Endpoint for admin to update an existing employee.
    """
    employee_obj = db.query(User).filter(User.UserID == employee_id).first()
    if not employee_obj:
        raise HTTPException(status_code=404, detail="Employee not found")

    if employee.organization_id:
        organization = db.query(Organization).filter(Organization.OrganizationID == employee.organization_id).first()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        employee_obj.OrganizationID = employee.organization_id

    if employee.username:
        employee_obj.Username = employee.username
    if employee.password:
        employee_obj.Password = get_password_hash(employee.password)
    if employee.email:
        employee_obj.Email = employee.email
    if employee.first_name:
        employee_obj.FirstName = employee.first_name
    if employee.last_name:
        employee_obj.LastName = employee.last_name
    if employee.role:
        employee_obj.Role = employee.role
    db.commit()
    db.refresh(employee_obj)

    return {"message": "Employee updated successfully"}

@app.delete("/admin/employee/delete/{employee_id}", dependencies=[Depends(has_role(UserRole.admin))])
async def delete_employee(employee_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for admin to delete an existing employee.
    """
    employee = db.query(User).filter(User.UserID == employee_id).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    db.delete(employee)
    db.commit()

    return {"message": "Employee deleted successfully"}