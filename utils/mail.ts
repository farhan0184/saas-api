import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";

export const sendTestEmail = async (email: string, mailtext: string) => {
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email, // Change to a valid recipient
        subject: "Test Email",
        text: mailtext,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log("Email sent successfully!");
    } catch (error) {
        console.error("Error sending email:", error);
    }
};


export const generateOTPToken = (email: string, otp: string, JWT_SECRET: string) => {
    const payload = {
        email: email,
        otp: otp,
    };

    // Generate a token with a payload containing email and otp, expires in 15 minutes
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
};


interface TokenPayload {
  email: string;
  otp: string;
  // Add other properties as per your token payload structure
}

export const verifyToken = (token: string, jwtSecret: string): Promise<TokenPayload> => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, jwtSecret, (err, decoded) => {
      if (err) {
        return reject('Invalid or expired token');
      }
      resolve(decoded as TokenPayload);
    });
  });
};

