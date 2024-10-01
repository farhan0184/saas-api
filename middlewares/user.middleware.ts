import { body, ValidationChain } from "express-validator";
import validate from "./validator.middleware";

const userRegisterValidator: ValidationChain[] = [
    body('name', "Name is required.")
        .exists()
        .notEmpty()
        .withMessage("Name must not be empty."),

    body('email', "Email is required.")
        .exists()
        .notEmpty()
        .withMessage("Email must not be empty.")
        .isEmail()
        .withMessage("Email is invalid."),

    body('password', "Password is required.")
        .exists()
        .notEmpty()
        .withMessage("Password must not be empty.")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters long."),

    body('confirm_password', "Confirm password is required.")
        .exists()
        .notEmpty()
        .withMessage("Confirm password must not be empty.")
        .isLength({ min: 6 })
        .withMessage("Confirm password must be at least 6 characters long.")
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Confirm password does not match password');
            }
            return true;
        }),
    body('role', "Role must be an array if provided.")
        .optional()  // Make the field optional
        .isArray()
        .withMessage("Role must be an array."),

    body('isAdmin', "isAdmin must be a boolean value.")
        .optional()  // The field is optional
        .toBoolean()  // Convert the value to boolean (true or false)
        .default(false)  // Set the default value to false
        .isBoolean()
        .withMessage("isAdmin must be a boolean value."),
];

export const userRegisterMiddleware = validate(userRegisterValidator);


const userEmailValidator: ValidationChain[] = [
    body('verification_code')
        .isNumeric()
        .withMessage('verify code must be a number')
        .isLength({ min: 6, max: 6 })
        .withMessage('verify code must be exactly 6 digits long')
]

export const userEmailMiddleware = validate(userEmailValidator);

const userLoginValidator: ValidationChain[] = [
    body('email', "Email is required.")
        .exists().notEmpty().withMessage("Email must not be empty.")
        .isEmail().withMessage("Email is invalid."),
    body('password', "Password is required.")
        .exists().notEmpty().withMessage("Password must not be empty.")
        .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long.")
]

export const userLoginMiddleware = validate(userLoginValidator)


const userForgetPasswordValidator: ValidationChain[] = [
    body('email', "Email is required.")
        .exists().notEmpty().withMessage("Email must not be empty.")
        .isEmail().withMessage("Email is invalid."),
]

export const userForgetPasswordMiddleware = validate(userForgetPasswordValidator)

const userResetPasswordValidator: ValidationChain[] = [
    body('password', "Password is required.")
        .exists().notEmpty().withMessage("Password must not be empty.")
        .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long."),
    body('confirm_password', "Confirm password is required.")
        .exists().notEmpty().withMessage("Confirm password must not be empty.")
        .isLength({ min: 6 }).withMessage("Confirm password must be at least 6 characters long.")
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Confirm password does not match password');
            }
            return true;
        })
]

export const userResetPasswordMiddleware = validate(userResetPasswordValidator)