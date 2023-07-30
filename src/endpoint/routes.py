import os
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_healthcheck import HealthCheckFactory, healthCheckRoute

from src.auth.auth_handler import (
    authenticate_user,
    create_access_token,
    get_current_active_user
)
from src.auth.fake_db import db
from src.config.constants import ACCESS_TOKEN_EXPIRE_MINUTES
from src.log_module.logger import get_logger_obj
from src.schema.models import Token, User

try:
    # templates = Jinja2Templates(directory="./src/static/templates")
    router = APIRouter()
    _healthChecks = HealthCheckFactory()
    # Get a logger object for the module by using the filename without the ".py" extension
    log = get_logger_obj(os.path.basename(__file__).replace(".py", ''))
except Exception as e:
    # If there's an error while initializing the logger, raise an exception and exit the program
    raise SystemExit(f"Unable to initialize app object in file {__name__}: {e}")


@router.post("/token/", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint to authenticate a user and provide an access token.

    This endpoint takes in the user's credentials (username and password) through the form_data parameter,
    authenticates the user using the AuthService's authenticate_user method, and if the user is valid,
    generates an access token using the AuthService's create_access_token method and returns it.

    Returns:
        Token: A Pydantic model containing the access token and token type.
    """
    # Log the login attempt with the username
    log.info(f"Login attempt for user: {form_data.username}")

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        # Log failed login attempts
        log.warning(f"Failed login attempt for user: {form_data.username}")

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect user name or password",
                            headers={"WWW-Authenticate": "Bearer"})

    # Log successful login
    log.info(f"User logged in successfully: {form_data.username}")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return {'access_token': access_token, "token_type": "bearer"}


@router.get('/users/me/', response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """
    Endpoint to get the current authenticated user's details.

    This endpoint takes in the current_user parameter, which is obtained from the AuthService's get_current_active_user
    method. It returns the current_user's details as a Pydantic User model.

    Returns:
        User: A Pydantic model containing the user details.
    """
    # Log the request to get the current user's details
    log.info(f"Request to get details for user: {current_user.username}")

    return current_user


@router.get('/users/me/items')
async def read_users_me_items(current_user: User = Depends(get_current_active_user)):
    """
    Endpoint to get the items owned by the current authenticated user.

    This endpoint takes in the current_user parameter, which is obtained from the AuthService's get_current_active_user
    method. It returns a list of items as a JSON response.

    Returns:
        List[dict]: A list of items, where each item is represented as a dictionary with item_id and owner keys.
    """
    # Log the request to get the current user's items
    log.info(f"Request to get items for user: {current_user.username}")

    return [{"item_id": 1, "owner": current_user.username}]


# Add Health Checks

router.add_api_route('/healthcheck', endpoint=healthCheckRoute(factory=_healthChecks))
