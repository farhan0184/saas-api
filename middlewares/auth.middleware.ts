import { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'

const secret = process.env.SECRET

export const decodeToken = (req: Request, res: Response, next: NextFunction) => {
    try {
        const token = req.headers?.authorization?.split(" ")[1];
        // console.log(token)

        res.locals.user = jwt.verify(token as string, secret as string);

        next();
    } catch (error) {
        next();
    }
};



export const isUser = (req: Request, res: Response, next: NextFunction) => {
    let { user } = res.locals
    if (!!user && !!user?._id) {
        next()
    } else {
        res.status(401).send({
            error: true,
            msg: 'Unauthorized'
        })
    }
}

export const isAdmin = (req: Request, res: Response, next: NextFunction) => {
    let {user} = res.locals
    
    console.log(user)
    if (!!user && !!user?._id && user.isAdmin === true) {
        next()
    } else {
        res.status(401).send({
            error: true,
            msg: 'Unauthorized'
        })
    }
}


export const isUserOrAdmin = (req: Request, res: Response, next: NextFunction) => {
    let { user } = res.locals;
    const userIdToUpdate = req.params.user_id; 

    if (!!user && !!user._id && (user._id === userIdToUpdate || user.isAdmin === true)) {
        next(); 
    } else {
        res.status(403).send({
            error: true,
            msg: 'Forbidden: You can only update your own profile'
        });
    }
};