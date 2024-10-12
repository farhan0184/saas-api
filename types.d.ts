import "express-session";
import { Session } from "@auth/express";

declare module "express-session" {
  interface SessionData {
    user?: {
      name?: string;
      id?: string;
    };
  }
}

declare module "@auth/express" {
  interface Session {
    accessToken?: string;
  }
}