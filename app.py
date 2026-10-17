
import time
import uuid

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-t56xj4cr.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI(title="OAuth 2.0 / OIDC Token Verification")


class VerifyRequest(BaseModel):
    token: str


@app.middleware("http")
async def add_response_headers(request: Request, call_next):
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = (
        f"{max(0.0, time.perf_counter() - start):.6f}"
    )
    return response


@app.post("/verify")
async def verify_token(body: VerifyRequest):
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "email", "sub"]
            },
        )

        return {
            "valid": True,
            "email": claims["email"],
            "sub": claims["sub"],
            "aud": claims["aud"],
        }

    except (InvalidTokenError, TypeError, ValueError, KeyError):
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )


@app.get("/")
async def root():
    return {"status": "ok", "endpoint": "/verify"}
