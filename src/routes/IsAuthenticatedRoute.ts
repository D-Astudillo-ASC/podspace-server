import { ApplicationRequest } from '../utils/ApplicationRequest';
import AuthUtils from '../utils/AuthUtils';
import BaseRoute from '../utils/BaseRoute';
import { RouteMethod } from '../utils/constants';

export default class IsAuthenticatedRoute extends BaseRoute<boolean> {
  constructor() {
    super({
      method: RouteMethod.GET,
      path: '/authenticated'
    });
  }

  /**
   * Returns true if the user making the request is authenticated, and false
   * otherwise.
   *
   * A request will be deemed "authenticated" if either the access token is
   * verified OR the refresh token is verified.
   *
   */
  async content(req: ApplicationRequest): Promise<boolean> {
    const { accessToken, refreshToken } = req.cookies;
    //Authenticated if either accessToken or refreshToken are verified.
    return (
      AuthUtils.verifyToken(accessToken) || AuthUtils.verifyToken(refreshToken)
    );
  }
}
