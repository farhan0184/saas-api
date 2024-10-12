import { NextFunction, Request, Response } from "express";

import passport from "passport";


export function handleCallback(platform: string) {
    return (req: Request, res: Response, next: NextFunction) => {
      passport.authenticate(platform, (err: any, user: any, info: any) => {
        if (err) {
          return next(err);
        }
        if (!user) {
          return res.redirect(`${process.env.FRONTEND_URL}/dashboard/account-manager` as string);
        }
  
        res.cookie(`${platform}Token`, user.accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          maxAge: 24 * 60 * 60 * 1000, // 1 day
        });
  
        return res.redirect(`${process.env.FRONTEND_URL}/dashboard/account-manager` as string);
      })(req, res, next);
    };
  }