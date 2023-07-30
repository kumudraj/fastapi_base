from pydantic import BaseModel

# Pydantic models

class Token(BaseModel):
    """
    Pydantic model representing the access token response.
from pydantic import BaseModel


# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str or None = None


class User(BaseModel):
    username: str
    email: str or None = None
    fullname: str or None = None
    disabled: bool or None = None


class UserInDB(User):
    hashed_password: str


class Data(BaseModel):
    name: str


    Attributes:
        access_token (str): The access token string.
        token_type (str): The type of the token (e.g., "bearer").
    """
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """
    Pydantic model representing the data contained in the access token.

    Attributes:
        username (str, optional): The username stored in the token. Defaults to None.
    """
    username: str or None = None


class User(BaseModel):
    """
    Pydantic model representing user details.

    Attributes:
        username (str): The username of the user.
        email (str, optional): The email address of the user. Defaults to None.
        fullname (str, optional): The full name of the user. Defaults to None.
        disabled (bool, optional): A flag indicating if the user is disabled. Defaults to None.
    """
    username: str
    email: str or None = None
    fullname: str or None = None
    disabled: bool or None = None


class UserInDB(User):
    """
    Pydantic model representing a user stored in the database.

    Attributes:
        hashed_password (str): The hashed password of the user.
    """
    hashed_password: str


class Data(BaseModel):
    """
    Pydantic model representing data with a single attribute 'name'.

    Attributes:
        name (str): The name attribute.
    """
    name: str
