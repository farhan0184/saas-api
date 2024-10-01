import mongoose, { Document, Model } from "mongoose";

// Define an interface for the user document
export interface IUser extends Document {
    name?: string;
    email?: string;
    password?: string;
    profile_image?: string;
    isAdmin?: boolean;
    role?: Array<String>;
    
}




// Create the user schema
const userSchema = new mongoose.Schema<IUser>({
    name: {
        type: String,
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    profile_image: {
        type: String,
        default: 'https://s3.amazonaws.com/37assets/svn/765-default-avatar.png'
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    role: {
        type: [String],
        default: []
    }
}, { timestamps: true });

const User: Model<IUser> = mongoose.model<IUser>('User', userSchema);

export default User;
