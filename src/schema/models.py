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

