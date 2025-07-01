from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# JWT secret (For demo use only! In production, load securely via environment variables)
SECRET_KEY = "notemaster_secret_key_please_change"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="Notemaster Notes API",
    version="1.0.0",
    description=(
        "FastAPI backend for Notemaster. "
        "Provides user authentication and CRUD operations on notes."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Frontend REACT will be on a different port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- Password Hashing -----

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


# ================== MODELS ==================


# PUBLIC_INTERFACE
class UserSignup(BaseModel):
    """User registration model."""
    username: str = Field(..., min_length=3, description="The username of the user.")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=4, description="Password for the account")


# PUBLIC_INTERFACE
class UserResponse(BaseModel):
    """Public user response."""
    username: str
    email: EmailStr


# PUBLIC_INTERFACE
class Token(BaseModel):
    """JWT response token"""
    access_token: str
    token_type: str


# PUBLIC_INTERFACE
class NoteCreate(BaseModel):
    """Create note model."""
    title: str = Field(..., description="Title of the note")
    content: Optional[str] = Field("", description="Text content of the note")


# PUBLIC_INTERFACE
class NoteUpdate(BaseModel):
    """Update note model."""
    title: Optional[str] = Field(None, description="Updated title")
    content: Optional[str] = Field(None, description="Updated content")


# PUBLIC_INTERFACE
class NoteResponse(BaseModel):
    """Response for note data."""
    id: int
    title: str
    content: str
    updated: datetime
    created: datetime
    owner: str


# ================== IN-MEMORY DBA ==================

# Simulated persistent store (replace with real DB in prod)
users_db: Dict[str, Dict] = {}        # username -> {username, email, hashed_password}
notes_db: Dict[int, Dict] = {}        # note_id -> note fields including owner
note_counter: int = 1                 # Global note ID counter


# ================== AUTH ==================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# PUBLIC_INTERFACE
def create_access_token(*, data: dict, expires_delta: timedelta = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    ))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get a current user based on JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in users_db:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return users_db[username]


# =============== AUTH ENDPOINTS ===============

@app.post(
    "/auth/signup",
    response_model=UserResponse,
    status_code=201,
    tags=["Auth"],
    summary="Register a new user",
)
# PUBLIC_INTERFACE
def register_user(user: UserSignup):
    """Registers a new user. Requires unique username and email."""
    if user.username in users_db:
        raise HTTPException(status_code=409, detail="Username already exists.")
    for u in users_db.values():
        if u["email"] == user.email:
            raise HTTPException(status_code=409, detail="Email already registered.")
    hashed = get_password_hash(user.password)
    users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed,
    }
    return UserResponse(username=user.username, email=user.email)


@app.post(
    "/auth/login",
    response_model=Token,
    tags=["Auth"],
    summary="User login",
)
# PUBLIC_INTERFACE
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return JWT token."""
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}


@app.get(
    "/auth/me",
    response_model=UserResponse,
    tags=["Auth"],
    summary="Get authenticated user",
)
# PUBLIC_INTERFACE
def get_me(current_user=Depends(get_current_user)):
    """Fetch details about the logged-in user."""
    return UserResponse(
        username=current_user["username"], email=current_user["email"]
    )


# =============== NOTES ENDPOINTS ===============

@app.post(
    "/notes/",
    response_model=NoteResponse,
    status_code=201,
    tags=["Notes"],
    summary="Create a note",
)
# PUBLIC_INTERFACE
def create_note(note: NoteCreate, current_user=Depends(get_current_user)):
    """Create a new note belonging to the authenticated user."""
    global note_counter
    new_id = note_counter
    now = datetime.utcnow()
    notes_db[new_id] = {
        "id": new_id,
        "title": note.title,
        "content": note.content or "",
        "owner": current_user["username"],
        "created": now,
        "updated": now,
    }
    note_counter += 1
    return NoteResponse(**notes_db[new_id])


@app.get(
    "/notes/",
    response_model=List[NoteResponse],
    tags=["Notes"],
    summary="List notes",
    response_description="A list of notes.",
)
# PUBLIC_INTERFACE
def list_notes(query: Optional[str] = None, current_user=Depends(get_current_user)):
    """
    List all notes belonging to the authenticated user.
    - **query**: Optional search string: filters notes whose title/content contain the string (case-insensitive).
    """
    user_notes = [
        note for note in notes_db.values() if note["owner"] == current_user["username"]
    ]
    if query:
        ql = query.lower()
        user_notes = [
            note
            for note in user_notes
            if ql in note["title"].lower() or ql in note["content"].lower()
        ]
    return [
        NoteResponse(**note)
        for note in sorted(user_notes, key=lambda n: n["updated"], reverse=True)
    ]


@app.get(
    "/notes/{note_id}",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Get a specific note",
)
# PUBLIC_INTERFACE
def get_note(note_id: int, current_user=Depends(get_current_user)):
    """Retrieve a single note by ID if owned by the current user."""
    note = notes_db.get(note_id)
    if not note or note["owner"] != current_user["username"]:
        raise HTTPException(status_code=404, detail="Note not found")
    return NoteResponse(**note)


@app.put(
    "/notes/{note_id}",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Update a note",
)
# PUBLIC_INTERFACE
def update_note(note_id: int, note_update: NoteUpdate, current_user=Depends(get_current_user)):
    """Edit a note. Only the owner can update their notes."""
    note = notes_db.get(note_id)
    if not note or note["owner"] != current_user["username"]:
        raise HTTPException(status_code=404, detail="Note not found")
    if note_update.title is not None:
        note["title"] = note_update.title
    if note_update.content is not None:
        note["content"] = note_update.content
    note["updated"] = datetime.utcnow()
    return NoteResponse(**note)


@app.delete(
    "/notes/{note_id}",
    status_code=204,
    tags=["Notes"],
    summary="Delete a note",
)
# PUBLIC_INTERFACE
def delete_note(note_id: int, current_user=Depends(get_current_user)):
    """Deletes a note instance. Only the owner can delete their notes."""
    note = notes_db.get(note_id)
    if not note or note["owner"] != current_user["username"]:
        raise HTTPException(status_code=404, detail="Note not found")
    del notes_db[note_id]
    return


# -------- API Health Endpoint --------

@app.get(
    "/",
    summary="Health check",
    include_in_schema=True,
    tags=["Meta"],
)
# PUBLIC_INTERFACE
def health_check():
    """Returns health status for the API."""
    return {"message": "Healthy"}


# -------- CUSTOM OPENAPI TAGS --------

openapi_tags = [
    {
        "name": "Auth",
        "description": (
            "User authentication endpoints (signup, login, "
            "get user info)"
        ),
    },
    {"name": "Notes", "description": "CRUD operations for notes."},
    {"name": "Meta", "description": "Service info and health check."}
]
app.openapi_tags = openapi_tags


def custom_openapi():
    """Enforces custom tags in OpenAPI."""
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=openapi_tags,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
