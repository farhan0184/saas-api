import { Router } from "express";
import passport from "passport";
import { Strategy as TwitterStrategy } from "passport-twitter"
import { handleCallback } from "../../utils/passport-auth-post";
import cookieSession from "cookie-session";
import cookieParser from "cookie-parser";

const postAuthRoutes = Router();

// isUserOrAdmin


postAuthRoutes.use(cookieSession({
    name: 'session',
    keys: [/* secret keys */],
    maxAge: 24 * 60 * 60 * 1000 // session will expire after 24 hours
}))
postAuthRoutes.use(cookieParser());
postAuthRoutes.use(passport.initialize());
postAuthRoutes.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user as any);
});

// Twitter strategy
passport.use(
    new TwitterStrategy(
        {
            consumerKey: process.env.TWITTER_CONSUMER_KEY as string,
            consumerSecret: process.env.TWITTER_CONSUMER_SECRET as string,
            callbackURL: "http://localhost:8080//v1/api/post-auth/twitter/callback",
        },
        function (token, tokenSecret, profile, cb) {
            return cb(null, { ...profile, accessToken: token });
        }
    )
);

postAuthRoutes.get("/twitter", passport.authenticate("twitter"));
postAuthRoutes.get("/twitter/callback", handleCallback("twitter"));

postAuthRoutes.get("/twitter/user", (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            isAuthenticated: true,
            user: req.user,
        });
    } else {
        res.json({ isAuthenticated: false });
    }
});


export default postAuthRoutes;