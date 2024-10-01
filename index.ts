import express, { NextFunction, Request, RequestHandler, Response } from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import apiRoutes from "./routes/api";
import { decodeToken } from "./middlewares/auth.middleware";
import helmet from "helmet";
import compression from "compression";
import { ExpressAuth } from "@auth/express";
import Facebook from "@auth/express/providers/facebook"


dotenv.config();


mongoose.connect(process.env.DATABASE_URL!).then(() => {
    console.log('MongoDB Connected Successfully.')
}).catch((err) => {
    console.log('Database connection failed.')
})

// console.log(process.env.SECRET)

const PORT: number = Number(process.env.PORT);

const app = express();

app.use(express.json())

// Use Helmet to secure your app by setting various HTTP headers
app.use(helmet());

// Use compression middleware to compress all responses
app.use(compression());







app.use(
    express.urlencoded({
        extended: true,
    })
);


app.use("/auth/*", ExpressAuth({
    providers: [
      Facebook({
        clientId: process.env.FACEBOOK_CLIENT_ID as string,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET as string,
        authorization: {
          params: {
            scope: "email,pages_show_list,pages_read_engagement,pages_manage_posts"
          }
        }
      })
    ]
  }));

app.use(function (req: Request, res: Response, next: NextFunction) {
    res.header("Access-Control-Allow-Origin", "*"); //* will allow from all cross domain
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept"
    )
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    next()
});
app.use(cors())
app.use(decodeToken)


app.use('/v1/api', apiRoutes)
app.get('/', (req: Request, res: Response) => {
    res.send('Welcome to Accounta!');
})

app.use((err: any, req: Request, res: Response, _: NextFunction) => {
    res.status(500).send({
        error: true,
        message: "Something went wrong."
    });
});

app.get('*', (req: Request, res: Response) => {
    res.send('Welcome to Accounta!');
})


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
})