/* eslint-disable prettier/prettier */
import { Response } from 'express';

import { ApplicationRequest } from '../utils/ApplicationRequest';
import BaseRoute from '../utils/BaseRoute';
import { RouteMethod } from '../utils/constants';

export default class LogoutRoute extends BaseRoute<boolean> {
  constructor() {
    super({
      /**
       * TODO: (9.01)
       * - Should the user be authenticated to hit this route?
       * - Replace null with the correct route type from the RouteMethod enum
       * in the constants.ts file.
       * - Fill in the path string with the appropriate path to this endpoint.
       * - Delete this comment.
       */
      authenticated: true,
      method: RouteMethod.POST,
      path: '/logout'
    });
  }

  /**
   * Should clear the access token and refresh token on the response, which
   * will effectively "logout" the user, since they will no longer have the
   * tokens (which they need to be authenticated).
   *
   * Returns true in all cases.
   */
  async content(_: ApplicationRequest, res: Response): Promise<boolean> {
    // TODO: (9.02) Use the res.clearCookie('') function to remove the
    // accessToken and refreshToken from their cookies. Return true after!
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    return true;
  }
}
