from fastapi.security import OAuth2PasswordRequestForm

from main import login_for_access_token


# Example function uses
def example_login():
    # Simulating a login request and receiving a response containing the access token
    form_data = OAuth2PasswordRequestForm(username="tim", password="tim123")
    response = login_for_access_token(form_data=form_data)
    print(response.access_token)  # Access token to be used for subsequent API requests


"""
def example_get_user_details():
    # Simulating an API request to get the user's details
    access_token = "..."  # Use the access token obtained after login
    headers = {"Authorization": f"Bearer {access_token}"}
    response = app.client.get("/users/me/", headers=headers)
    print(response.json())  # User details of the authenticated user


def example_get_user_items():
    # Simulating an API request to get the items owned by the user
    access_token = "..."  # Use the access token obtained after login
    headers = {"Authorization": f"Bearer {access_token}"}
    response = app.client.get("/users/me/items", headers=headers)
    print(response.json())  # List of items owned by the authenticated user
"""
# print(auth_service.get_password_hash("tim123"))  # Uncomment to hash a new password
