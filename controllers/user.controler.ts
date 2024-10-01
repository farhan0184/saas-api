import { Request, Response } from "express";
import User, { IUser } from "../models/user.model";
import bcrypt from 'bcrypt';


// create user
export const useUserCreate = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { name, email, password, role } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }


        const hashedPassword = await bcrypt.hash(password, 10);
        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            role: role || []
        });
        await user.save();



        return res.status(200).json({
            success: true,
            msg: "User created successfully.",
            data: user
        })
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            msg: "Something went wrong."
        });
    }
}

// find all user
export const useUserList = async (req: Request, res: Response): Promise<Response> => {
    try {
        const users = await User.find();
        // Map over users and exclude the password using destructuring
        if (users.length === 0) {
            return res.status(200).json({
                success: true,
                msg: "No users found.",
                data: [] // Return an empty array
            });
        }

        const usersWithoutPasswords = users?.map(user => {
            const { password, ...rest } = user.toObject(); // Convert Mongoose document to plain object and exclude password
            return rest;
        });

        return res.status(200).json({
            success: true,
            msg: "Users fetched successfully.",
            data: usersWithoutPasswords,
            totalUser: users.length
        })
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            msg: "Something went wrong."
        });
    }
}

// find one user
export const useFindUser = async (req: Request, res: Response): Promise<Response> => {
    try {
        const user_id = req.params.user_id;
        // console.log(req.params)
        const user = await User.findById(user_id);

        if (!user) {
            return res.status(404).json({
                success: false,
                msg: "User not found."
            });
        }

        // Exclude the password field from the response
        const { password, ...userWithoutPassword } = user.toObject();

        return res.status(200).json({
            success: true,
            msg: "User fetched successfully.",
            data: userWithoutPassword
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            msg: "Something went wrong."
        });
    }
};


// update user
export const useUpdateUser = async (req: Request, res: Response): Promise<Response> => {
    try {
        const user_id = req.params.user_id;

        let updateData = { ...req.body }; 

        // console.log(updateData)

        // Fetch the current user data from the database
        const currentUser: any = await User.findById(user_id);

        if (!currentUser) {
            return res.status(404).json({
                success: false,
                msg: "User not found."
            });
        }

        // Check if the email is present in the update request
        if (updateData.email || updateData._id) {
            return res.status(400).json({
                success: false,
                msg: "Email & User Id cannot be updated."
            });
        }

        if(updateData.isAdmin && !currentUser.isAdmin) {
            return res.status(400).json({
                success: false,
                msg: "You are not Admin. You cannot update your role."
            })
        }
        
         // Filter out any fields with empty strings
         Object.keys(updateData).forEach(key => {
            if (updateData[key] === '' || currentUser[key] === updateData[key]) {
                delete updateData[key];
            }
            // If the key is 'password', hash the password before updating
            if (key === 'password') {
                updateData[key] =  bcrypt.hash(updateData[key], 10); 
            }
        });


        if (!currentUser) {
            return res.status(404).json({
                success: false,
                msg: "User not found."
            });
        }

        // Check if the data has actually changed
        const isDataChanged = Object.keys(updateData).some(key => currentUser[key] !== updateData[key]);

        // If no changes, return a message indicating that nothing was updated
        if (!isDataChanged) {
            return res.status(400).json({
                success: false,
                msg: "No changes detected. Nothing was updated."
            });
        }

        // Proceed with updating the user
        const updatedUser: any = await User.findByIdAndUpdate(user_id, updateData, {
            new: true,  
        });

        // Exclude password from the response
        const { password,isAdmin, ...restUser } = updatedUser.toObject();

        return res.status(200).json({
            success: true,
            msg: "User updated successfully.",
            data: restUser
        });



    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            msg: "Something went wrong.",
        })
    }
}

// delete user
export const useDeleteUser = async (req: Request, res: Response): Promise<Response> => {
    try {
        const user_Id = req.params.user_id;  // Assuming the user ID is passed as a URL parameter

        // Attempt to find and delete the user
        const deletedUser = await User.findByIdAndDelete(user_Id);

        if (!deletedUser) {
            return res.status(404).json({
                success: false,
                msg: "User not found."
            });
        }

        return res.status(200).json({
            success: true,
            msg: "User deleted successfully.",
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: true,
            msg: "Something went wrong."
        });
    }
};