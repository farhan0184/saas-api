import { Request, Response, NextFunction } from "express";
import { validationResult, ValidationChain } from "express-validator";

const validate = (validations: ValidationChain[]) => async (req: Request, res: Response, next: NextFunction) => {
    // Run all validations concurrently
    await Promise.all(validations.map(validation => validation.run(req)));

    // Check for validation errors
    const errors = validationResult(req);
    if (errors.isEmpty()) {
        return next(); // No errors, proceed to the next middleware
    }

    return res.status(422).send({
        error: true,
        msg: errors.array()[0].msg, // Return the first error message
    });
};

export default validate;
