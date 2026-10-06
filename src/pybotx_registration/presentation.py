from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

from pybotx_registration.application import RegisterBotCommand
from pybotx_registration.domain import (
    AlreadyRegisteredError,
    InvalidRegistrationRequestError,
    RegistrationAuthenticationError,
    SecretDecryptionError,
)
from pybotx_registration.ports import (
    RegistrationAuthenticator,
    RegistrationHttpService,
)


class PublicKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = "ok"
    result: str


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    bot_id: Annotated[str, Field(min_length=1, max_length=256)]
    encrypted_secret_key: Annotated[str, Field(min_length=64, max_length=16_384)]
    server_id: Annotated[str, Field(min_length=1, max_length=256)]
    server_host: Annotated[str, Field(min_length=1, max_length=2_048)]


class RegisteredResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = "ok"
    result: str = "registered"


class AlreadyRegisteredResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = "error"
    reason: str = "already_registered"
    errors: list[object] = Field(default_factory=list)
    error_data: dict[str, object] = Field(default_factory=dict)


def create_registration_router(
    *,
    service: RegistrationHttpService,
    authenticator: RegistrationAuthenticator,
) -> APIRouter:
    router = APIRouter(tags=["BotX registration"])

    async def authenticate(request: Request) -> str:
        try:
            return await authenticator.authenticate(request)
        except RegistrationAuthenticationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN) from exc

    @router.get("/public_key", response_model=PublicKeyResponse)
    async def get_public_key(_: str = Depends(authenticate)) -> PublicKeyResponse:
        return PublicKeyResponse(result=await service.public_key_base64())

    @router.post(
        "/register",
        response_model=RegisteredResponse,
        status_code=status.HTTP_201_CREATED,
        responses={400: {"model": AlreadyRegisteredResponse}},
    )
    async def register(
        payload: RegisterRequest,
        request: Request,
        _: str = Depends(authenticate),
    ) -> RegisteredResponse | JSONResponse:
        try:
            await service.register(
                RegisterBotCommand(
                    bot_id=payload.bot_id,
                    server_id=payload.server_id,
                    server_host=payload.server_host,
                    encrypted_secret_key=payload.encrypted_secret_key,
                    request_id=request.headers.get("X-Request-Id"),
                )
            )
        except AlreadyRegisteredError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=AlreadyRegisteredResponse().model_dump(),
            )
        except (InvalidRegistrationRequestError, SecretDecryptionError) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST) from exc
        return RegisteredResponse()

    return router
