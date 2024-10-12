import {Request, Response, Router} from "express";
import authRoutes from "./api/auth.route";
import userRoutes from "./api/user.route";
import postAuthRoutes from "./api/postAuth.route";
import { isLoggedIn, isUser } from "../middlewares/auth.middleware";
import { getUser } from "../controllers/auth.controler";


const apiRoutes = Router();


apiRoutes.use("/auth", authRoutes);
apiRoutes.use('/users', userRoutes)
apiRoutes.get('/user',isLoggedIn, getUser)
apiRoutes.use('/post-auth', postAuthRoutes)


export default apiRoutes