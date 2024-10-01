import { Router } from "express";

import { resendVerificationCode, useForgetPassword, useLogin, useResetPassword, userRegister, verifyCode } from "../../controllers/auth.controler";
import { userForgetPasswordMiddleware, userLoginMiddleware, userRegisterMiddleware, userResetPasswordMiddleware } from "../../middlewares/user.middleware";


const authRoutes = Router();

authRoutes.post('/register', userRegisterMiddleware ,userRegister)
authRoutes.post('/verify-email', verifyCode)
authRoutes.post('/resend-code', resendVerificationCode)
authRoutes.post('/login', userLoginMiddleware, useLogin)
authRoutes.post('/forgot-password', userForgetPasswordMiddleware, useForgetPassword)
authRoutes.post('/reset-password', userResetPasswordMiddleware, useResetPassword)





export default authRoutes;