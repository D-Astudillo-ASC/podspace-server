import { UserDocument } from '../models/User';
import { ApplicationRequest } from '../utils/ApplicationRequest';
import BaseRoute from '../utils/BaseRoute';
import { RouteMethod } from '../utils/constants';
import { IdArgs } from '../utils/types';

export default class GetMeRoute extends BaseRoute<UserDocument> {
  constructor() {
    super({
      authenticated: true,
      method: RouteMethod.GET,
      path: '/me'
    });
  }

  /**
   * Returns the logged-in user.
   */
  async content(req: ApplicationRequest<IdArgs>): Promise<UserDocument> {
    return req.user;
  }
}
