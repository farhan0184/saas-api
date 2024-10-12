import express, { NextFunction, Request, RequestHandler, Response } from "express";

import mongoose from "mongoose";

import apiRoutes from "./routes/api";
import { decodeToken } from "./middlewares/auth.middleware";
import helmet from "helmet";


import dotenv from "dotenv";
import compression from "compression";
import cors from "cors";

dotenv.config();


mongoose.connect(process.env.DATABASE_URL!).then(() => {
    console.log('MongoDB Connected Successfully.')
}).catch((err) => {
    console.log('Database connection failed.')
})

// console.log(process.env.SECRET)



const PORT = process.env.PORT || 8080;

const app = express();

app.use(express.json())

// Use Helmet to secure your app by setting various HTTP headers
// app.use(helmet());

// Use compression middleware to compress all responses
app.use(compression());

app.use(
    express.urlencoded({
        extended: true,
    })
);






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