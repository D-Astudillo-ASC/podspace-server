import { Response } from 'express';
import { body } from 'express-validator';

import AuthCode, { AuthCodeDocument } from '../models/AuthCode';
import User, { UserDocument } from '../models/User';
import { ApplicationRequest } from '../utils/ApplicationRequest';
import BaseRoute from '../utils/BaseRoute';
import { RouteMethod } from '../utils/constants';
import MiddlewareUtils from '../utils/MiddlewareUtils';
import RouteError from '../utils/RouteError';

type VerifyCodeBody = Pick<AuthCodeDocument, 'phoneNumber'> & {
  code: number;
};

type VerifyCodeRequest = ApplicationRequest<{}, VerifyCodeBody>;

export default class VerifyCodeRoute extends BaseRoute<boolean> {
  constructor() {
    super({
      method: RouteMethod.POST,
      path: '/verify'
    });
  }

  /**
   * Validate the following inputs:
   *  - body.code
   *  - body.phoneNumber
   */
  middleware() {
    return [
      body('phoneNumber')
        .isMobilePhone('en-US')
        .withMessage('The phone number you inputted was not valid.')
        .custom((phoneNumber: string) => {
          return MiddlewareUtils.isFound(AuthCode, { phoneNumber });
        })
        .withMessage({
          message: 'Are you sure you received an authentication code?',
          statusCode: 404
        }),
      body('code')
        .isNumeric()
        .isLength({ max: 6, min: 6 })
        .withMessage({ message: 'Invalid OTP format.', statusCode: 400 })
    ];
  }

  /**
   * Validates that the OTP code given matches the OTP code associated with
   * the given phone number. If the OTP code does not match, should throw a 401
   * error.
   *
   * If the code is correct, then we should generate new authentication tokens
   * for the user and store them on the response. Also, if a user didn't
   * previously exist, we should create one associated with the phone number
   * at this point.
   *
   * @throws {RouteError} - If the code does not match what is in DB.
   */
  async content(req: VerifyCodeRequest, res: Response): Promise<boolean> {
    const reqCode: number = req.body.code;
    const reqPhone: string = req.body.phoneNumber;
    const dbRes = await AuthCode.findOne({ phoneNumber: reqPhone });
    const dbCode: number = dbRes.value;
    
    if (dbCode !== reqCode) {
      throw new RouteError({
        message: 'Given OTP code is incorrect.',
        statusCode: 401
      });
    }
    let user: UserDocument = await User.findOne({ phoneNumber: reqPhone });

    // User.findOne returns null if there is no registered user with phoneNumber = reqPhone in the DB.
    // If the user document obtained from the DB is null, we'll just create a new user with phoneNumber = reqPhone.
    if (!user) {
      user = await User.create({ phoneNumber: reqPhone });
    }
    // Renew's the user's tokens and attaches these new tokens on the
    // Express response object to send back to the client.
    const { accessToken, refreshToken } = await user.renewToken();
    MiddlewareUtils.attachTokens(res, { accessToken, refreshToken });

    await AuthCode.deleteOne({ _id: dbRes._id });
    return true;
  }
}
