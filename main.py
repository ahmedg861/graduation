from fastapi import FastAPI, HTTPException,  status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
# from typing import List, Optional
import json
file_path = r"data.json"
with open(file_path, "r") as file:
    data = json.load(file)

app = FastAPI()


registered_users = {}



class UserRegistration(BaseModel):
    username: str
    password: str
    email: str



class UserLogin(BaseModel):
    username: str
    password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



def verify_user_credentials(username: str, password: str):
    if username in registered_users and registered_users[username]['password'] == password:
        return True
    return False


@app.post("/register")
def register(user: UserRegistration):
    for x in data :
        if x['username'] in registered_users:
          raise HTTPException(status_code=400, detail="Username already registered")

    newuser=dict(user)
    newuser["id"] = max([t["id"] for t in data], default=0) + 1
    data.append(newuser)
    with open("data.json", "w") as file:
        json.dump(data, file, indent=2)

    # hashed_password = user.password
    # registered_users[user.username] = {"username": user.username, "password": hashed_password, "email": user.email}

    return {"message": "Registration successful"}



@app.post("/login")
async def login(user: UserLogin):

    username = user.username
    password = user.password
    for x in data:
        if x['username'] ==username and x['password'] == password:
         return {"message": "Login successful"}
    # if not verify_user_credentials(username, password):
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
