import { Router } from "express";
import { useDeleteUser, useFindUser, useUpdateUser, useUserCreate, useUserList } from "../../controllers/user.controler";
import { isAdmin, isUser, isUserOrAdmin } from "../../middlewares/auth.middleware";
import { userRegisterMiddleware } from "../../middlewares/user.middleware";

const userRoutes = Router();



userRoutes.post('/create-user',isAdmin,userRegisterMiddleware, useUserCreate)
userRoutes.put('/:user_id',isUserOrAdmin, useUpdateUser)
userRoutes.delete('/:user_id',isUserOrAdmin, useDeleteUser)
userRoutes.get('/:user_id',isAdmin,useFindUser)
userRoutes.get('/',isAdmin,useUserList)



export default userRoutes;