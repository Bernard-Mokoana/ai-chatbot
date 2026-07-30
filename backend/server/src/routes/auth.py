from backend.database.config.databaseConfig import get_write_db
from backend.server.src.schema.auth import (
    ForgetPasswordSchema,
    LoginSchema,
    RegisterSchema,
    ResetPasswordSchema,
)
from backend.server.src.services.auth_services import AuthService
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from sqlalchemy.orm import Session

import logging

logger = logging.getLogger("uvicorn.error")

auth = APIRouter(prefix="/api/v1/auth", tags=["auth"])
auth_service = AuthService()


@auth.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterSchema, db: Session = Depends(get_write_db)):
    try:
        user = auth_service.register_user(
            db=db, name=payload.name, email=payload.email, password=payload.password
            )
        return {
            "message": "User created successfully",
            "user": str(user.id),
            "email": user.email,
            }
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration error: {str(e)}")


@auth.post("/login", status_code=status.HTTP_200_OK)
async def login(
    payload: LoginSchema,
    response: Response,
    request: Request,
    db: Session = Depends(get_write_db),
):
    user = auth_service.authenticate_user(
        db=db, email=payload.email, password=payload.password
    )
    return auth_service.login(db=db, user=user, request=request, response=response)


@auth.post("/refresh")
async def refresh_token(
    request: Request, response: Response, db: Session = Depends(get_write_db)
):
    return auth_service.refresh_access_token(db=db, request=request, response=response)


@auth.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    request: Request, response: Response, db: Session = Depends(get_write_db)
):
    return auth_service.logout(db=db, request=request, response=response)


@auth.get("/verify-email")
async def verify_email(token: str, db: Session = Depends(get_write_db)):
    return auth_service.verify_email_token(db=db, token_str=token)


@auth.post("/forgot-password")
async def forgot_password(
    payload: ForgetPasswordSchema, db: Session = Depends(get_write_db)
):
    return auth_service.request_password_reset(db=db, email=payload.email)


@auth.post("/reset-password")
async def reset_password(
    payload: ResetPasswordSchema, db: Session = Depends(get_write_db)
):
    return auth_service.reset_password(
        db=db, token_str=payload.token, new_password=payload.new_password
    )
