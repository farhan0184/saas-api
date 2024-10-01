import {Request, Response, Router} from "express";
import authRoutes from "./api/auth.route";
import userRoutes from "./api/user.route";


const apiRoutes = Router();


apiRoutes.use("/auth", authRoutes);
apiRoutes.use('/users', userRoutes)


export default apiRoutes