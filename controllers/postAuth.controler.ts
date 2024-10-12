import { Request, Response } from "express";
import passport from "passport";
import { Strategy as FacebookStrategy } from "passport-facebook"


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID!,
    clientSecret: process.env.FACEBOOK_APP_SECRET!,
    callbackURL: `${process.env.FRONTEND_URL}/dashboard/account-manager`,
    profileFields: ['id', 'displayName'],
    scope: ['email', 'publish_pages', 'manage_pages']
}, (accessToken, refreshToken, profile, done) => {
    done(null, { id: profile.id, accessToken, displayName: profile.displayName });
}));