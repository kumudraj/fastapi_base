import os
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.auth.fake_db import db
from src.config.constants import SECRET_KEY, ALGORITHM
from src.log_module.logger import get_logger_obj
from src.schema.models import UserInDB, TokenData

log = get_logger_obj(os.path.basename(__file__).replace(".py", ''))

# Password hashing and verification setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 Password Bearer scheme setup
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Define a function to verify a plain password against a hashed password
def verify_password(plain_password, hashed_password) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        log.error(f"Error occurred while verifying password: {e}")
        return False


# Define a function to get the hash of a password
def get_password_hash(password) -> str:
    try:
        return pwd_context.hash(password)
    except Exception as e:
        log.error(f"Error occurred while hashing password: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Password hashing error")


# Define a function to get a user from the database based on their username
def get_user(db, username: str):
    try:
        if username in db:
            user_data = db[username]
            return UserInDB(**user_data)
    except Exception as e:
        log.error(f"Error occurred while fetching user from database: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")


# Define a function to authenticate a user based on their credentials
def authenticate_user(db, username: str, password: str):
    try:
        log.info(f"Authenticating: {username}")
        user = get_user(db, username)
        if not user:
            log.warning(f"{username} is not a valid user")
            return False

        if not verify_password(password, user.hashed_password):
            log.warning(f"Invalid password for user: {username}")
            return False

        return user

    except Exception as e:
        log.error(f"Error occurred while authenticating user: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication error")


# Define a function to create an access token with optional expiration
def create_access_token(data: dict, expires_delta: timedelta or None = None) -> str:
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    except Exception as e:
        log.error(f"Error occurred while creating access token: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token creation error")


# Define an asynchronous function to get the current user from a provided token
async def get_current_user(token: str = Depends(oauth_2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Could not validate credentials",
                                          headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError as e:
        log.error(f"Error occurred while decoding JWT: {e}")
        raise credentials_exception

    try:
        user = get_user(db, username=token_data.username)

        if user is None:
            log.warning(f"User not found in the database: {token_data.username}")
            raise credentials_exception

        return user

    except Exception as e:
        log.error(f"Error occurred while fetching user from database: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")


# Define an asynchronous function to get the current active user based on the provided current_user dependency
async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    try:
        if current_user.disabled:
            log.warning(f"Inactive user: {current_user.username}")
            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user

    except Exception as e:
        log.error(f"Error occurred while fetching current active user: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
