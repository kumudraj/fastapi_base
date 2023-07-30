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
    """
    Verify the given plain password against the given hashed password.

    Parameters:
    plain_password (str): The plain password to verify.
    hashed_password (str): The hashed password to compare against.

    Returns:
    bool: True if the plain password matches the hashed password, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


# Define a function to get the hash of a password
def get_password_hash(password) -> str:
    """
    Get the hashed version of the provided password.

    Parameters:
    password (str): The password to hash.

    Returns:
    str: The hashed password.
    """
    return pwd_context.hash(password)


# Define a function to get a user from the database based on their username
def get_user(db, username: str):
    """
    Get a user from the database based on their username.

    Parameters:
    db (dict): The database containing user data.
    username (str): The username of the user to retrieve.

    Returns:
    UserInDB or None: The user data if found, None if the user does not exist in the database.
    """
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)


# Define a function to authenticate a user based on their credentials
def authenticate_user(db, username: str, password: str):
    """
    Authenticate a user based on their credentials.

    Parameters:
    db (dict): The database containing user data.
    username (str): The username of the user to authenticate.
    password (str): The plain password to verify.

    Returns:
    UserInDB or False: The user data if authentication succeeds, False if the user does not exist in the database.
    """
    log.info(f"Authenticating: {username}")
    user = get_user(db, username)
    if not user:
        log.warning(f"{username} is not a valid user")
        return False
    return user


# Define a function to create an access token with optional expiration
def create_access_token(data: dict, expires_delta: timedelta or None = None) -> str:
    """
    Create an access token with optional expiration.

    Parameters:
    data (dict): The data to include in the access token.
    expires_delta (timedelta or None, optional): The optional time delta for token expiration. If None, the token will expire in 15 minutes.

    Returns:
    str: The encoded access token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Define an asynchronous function to get the current user from a provided token
async def get_current_user(token: str = Depends(oauth_2_scheme)):
    """
    Get the current user based on the provided token.

    Parameters:
    token (str, optional): The JWT token for authentication. Obtained from the "Authorization" header in the request.

    Returns:
    UserInDB: The current user if authentication is successful.

    Raises:
    HTTPException: If the provided token is invalid or the user is not found in the database.
    """
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Could not validate credentials",
                                          headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)

    if user is None:
        raise credentials_exception
    return user


# Define an asynchronous function to get the current active user based on the provided current_user dependency
async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    """
    Get the current active user based on the provided current_user dependency.

    Parameters:
    current_user (UserInDB): The user obtained from the get_current_user function.

    Returns:
    UserInDB: The current active user if they are not disabled.

    Raises:
    HTTPException: If the current user is disabled.
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
