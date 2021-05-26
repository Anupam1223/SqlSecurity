from sqlalchemy import engine
from sqlsecurity.database import LocalSession, engine
from sqlsecurity import models, schema, crud
from sqlalchemy.orm import Session
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta, datetime
from jose import JWTError, jwt
import uvicorn

models.Base.metadata.create_all(bind=engine)

# -------------------------- info regarding token -----------------------------
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# -----------------------------------------------------------------------------
app = FastAPI()


def get_user():
    db = LocalSession()
    try:
        yield db
    finally:
        db.close()


# ---------------------- Creating token -------------------------------------
def create_access_token(data: dict, expires_delta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ---------------------------------------------------------------------------

# ----------------------------------------------------------------------------
@app.post("/create_user/", response_model=schema.UserResponse)
def create_user(user: schema.CreateUser, db: Session = Depends(get_user)):
    return crud.create_user(db, user)


# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
@app.post("/verify_user", response_model=schema.Token)
async def login_for_access_token(
    form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_user)
):
    user_value = crud.read_user(db, form.username)
    username = user_value.username
    password = user_value.password
    hash_password = crud.get_password_hash(password)
    verify_password = crud.check_password(password, hash_password)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username is incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="password is incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user": username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --------------------------------------------------------------------------------

# -------------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
# --------------------------------------------------------------------------------
