import { Request, Response } from "express";
import dotenv from "dotenv";
import User, { IUser } from "../models/user.model"; // Adjust the import path as necessary
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { generateOTPToken, sendTestEmail, verifyToken } from "../utils/mail";

// Load environment variables
dotenv.config();

const SECRET = process.env.SECRET;

const VERIFICATION_CODE_EXPIRATION = 2 * 60 * 1000;

// verification code
const verificationCodes: {
    [email: string]: {
        code: string,
        expiresAt: number,
        timer: NodeJS.Timeout
    }
} = {};


// Helper function to generate a random verification code
const generateVerificationCode = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
};


// Helper function to set verification code and timer
const setVerificationCode = (email: string, code: string) => {
    // Clear existing timer if there is one
    if (verificationCodes[email] && verificationCodes[email].timer) {
        clearTimeout(verificationCodes[email].timer);
    }

    const expiresAt = Date.now() + VERIFICATION_CODE_EXPIRATION;
    const timer = setTimeout(() => {
        delete verificationCodes[email];
    }, VERIFICATION_CODE_EXPIRATION);

    verificationCodes[email] = { code, expiresAt, timer };
};



// user register 
export const userRegister = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { body } = req;

        // Check if the email already exists
        const existingUser = await User.findOne({ email: body.email });
        if (existingUser) {
            return res.status(409).json({
                error: true,
                msg: "Email already exists."
            });
        }



        // Create a new user
        const newUser = {
            name: body.name,
            email: body.email,
            password: body.password,
        }

        // Generate verification code
        const verificationCode = generateVerificationCode();

        const mailtext = `Your verification code is: ${verificationCode}`
        await sendTestEmail(body.email, mailtext);

        // Set verification code and timer
        setVerificationCode(body.email, verificationCode);


        // const hashPassword = await bcrypt.hash(body.password, 10);
        // // Create a new user instance
        // const user = new User({
        //     name:  body.name,
        //     email: body.email,
        //     password: hashPassword,
        // });

        // // Save the user to the database
        // await user.save();


        // Return success response
        return res.status(200).json({
            data: newUser,
            message: "Verification code sent. Please verify within 2 minutes."
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            msg: "Something went wrong."
        });
    }
};

// verify the registration
export const verifyCode = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { newUser, code } = req.body;
        // console.log(newUser, code);

        const storedVerification = verificationCodes[newUser.email];

        if (!storedVerification) {
            return res.status(400).json({
                error: true,
                msg: "Verification code has expired or does not exist."
            });
        }

        if (storedVerification.code !== code) {
            return res.status(400).json({
                error: true,
                msg: "Invalid verification code."
            });
        }

        if (Date.now() > storedVerification.expiresAt) {
            clearTimeout(storedVerification.timer);
            delete verificationCodes[newUser.email];
            return res.status(400).json({
                error: true,
                msg: "Verification code has expired."
            });
        }

        // Code is valid and not expired, proceed with user registration
        clearTimeout(storedVerification.timer);
        delete verificationCodes[newUser.email]; // Remove the used code



        const hashPassword = await bcrypt.hash(newUser.password, 10);
        // Create a new user instance
        const user = new User({
            name: newUser.name,
            email: newUser.email,
            password: hashPassword,
        });

        // Save the user to the database
        await user.save();



        return res.status(201).json({
            success: true,
            msg: "Email verified and user registered successfully.",
        });

    } catch (error) {
        console.error('Error in verifyCode:', error);
        return res.status(500).json({
            error: true,
            msg: "An error occurred while verifying the code and registering the user."
        });
    }
};

// reset the code
export const resendVerificationCode = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { email } = req.body;

        // Generate new verification code
        const newVerificationCode = generateVerificationCode();

        const mailtext = `Your verification code is: ${newVerificationCode}`
        await sendTestEmail(email, mailtext);



        // Set new verification code and restart timer
        setVerificationCode(email, newVerificationCode);

        return res.status(200).json({
            success: true,
            message: "New verification code sent. Please verify within 2 minutes."
        });

    } catch (error) {
        console.error('Error in resendVerificationCode:', error);
        return res.status(500).json({
            error: true,
            msg: "An error occurred while resending the verification code."
        });
    }
};


// user login
export const useLogin = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email }).select('+password');

        if (!user) {
            return res.status(401).json({
                error: true,
                msg: "Invalid credentials."
            });
        }

        // Check password
        const isPasswordValid =  bcrypt.compare(password, user?.password as string);
        if (!isPasswordValid) {
            return res.status(401).json({
                error: true,
                msg: "Invalid credentials."
            });
        }
        // console.log(user)

        // Generate JWT token
        const token = jwt.sign(
            { _id: user?._id, isAdmin: user?.isAdmin, role: user?.role },
            SECRET as string,
            { expiresIn: '1d' }
        );

        return res.status(200).json({
            success: true,
            msg: "Login successful.",
            token
        });

    } catch (error) {
        console.error('Error in login:', error);
        return res.status(500).json({
            error: true,
            msg: "An error occurred during login."
        });
    }
};

// forgot password
export const useForgetPassword = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { email } = req.body;

        const otp = generateVerificationCode();

        // generate token with email and otp
        const token = generateOTPToken(email, otp, SECRET as string);

        // send email
        const mailtext = `Your reset-password link is: http://localhost:3000/reset-password?token=${token}`;
        await sendTestEmail(email, mailtext);


        return res.status(200).json({
            success: true,
            msg: "OTP sent. Please check your email.",
            token
        });
    }
    catch (error) {
        console.error('Error in forgetPassword:', error);
        return res.status(500).json({
            error: true,
            msg: "An error occurred while resetting the password."
        });
    }
}

// reset password
export const useResetPassword = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { password, otp_token } = req.body;
        if (!otp_token) {
            return res.status(403).json({ message: 'Token is required' });
        }

        const decodedToken = await verifyToken(otp_token, SECRET as string);

        console.log('Decoded token:', decodedToken);
        const email = decodedToken.email;



        // Find user and update password
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                error: true,
                msg: "User not found.",
            });
        }

        // Update password (assuming you have a setPassword method on your User model)
        user.password = bcrypt.hashSync(password, 10);
        await user.save();



        return res.status(200).json({
            success: true,
            msg: "Password reset successfully.",
        });
    }
    catch (error) {
        console.error('Error in resetPassword:', error);
        return res.status(500).json({
            error: true,
            msg: "An error occurred while resetting the password."
        });
    }
}

