import { body } from 'express-validator';
import multer from 'multer';

import User, { UserDocument } from '../models/User';
import ImageService from '../services/ImageService';
import { ApplicationRequest } from '../utils/ApplicationRequest';
import BaseRoute from '../utils/BaseRoute';
import { APP, RouteMethod } from '../utils/constants';
import { IdArgs } from '../utils/types';
import Utils from '../utils/Utils';

type UpdateMeBody = Pick<
  UserDocument,
  'firstName' | 'lastName' | 'instagramUrl' | 'linkedInUrl' | 'twitterUrl'
>;

export default class UpdateMeRoute extends BaseRoute<UserDocument> {
  constructor() {
    super({
      authenticated: true,
      method: RouteMethod.PATCH,
      path: '/me'
    });
  }

  middleware() {
    return [
      body('firstName')
        .if((value: string) => Utils.isDefined(value))
        .isLength({ min: 1 })
        .withMessage('First name cannot be empty.'),

      body('lastName')
        .if((value: string) => Utils.isDefined(value))
        .isLength({ min: 1 })
        .withMessage('Last name cannot be empty.'),

      body('instagramUrl')
        .if((value: string) => Utils.isDefined(value) && !!value.length)
        .isURL()
        .withMessage('The Instagram URL must be a valid URL.'),

      body('linkedInUrl')
        .if((value: string) => Utils.isDefined(value) && !!value.length)
        .isURL()
        .withMessage('The LinkedIn URL must be a valid URL.'),

      body('twitterUrl')
        .if((value: string) => Utils.isDefined(value) && !!value.length)
        .isURL()
        .withMessage('The Twitter URL must be a valid URL.')
    ];
  }

  /**
   * Updates the logged-in user and persists the changes to the database.
   *
   * Should use the Utils.cleanObject() to ensure we don't save any "undefined"
   * values on the User.
   *
   * @returns The updated user.
   */
  async content(
    req: ApplicationRequest<IdArgs, UpdateMeBody>
  ): Promise<UserDocument> {
    // TODO: (12.03) Read this function and all comments and try to understand
    // what's going on :)

    // We allow this to be undefined, b/c if it is, the cleanObject(), will
    // simply remove it from the update body.
    let profilePictureKey: string;

    // If the user uploaded a profile picture file, then we want to process it!
    if (req.file) {
      // Extract the key information/content from the file.
      const { buffer, mimetype: mimeType } = req.file;

      const currentTimestamp = Date.now();

      // Construct the key that will determine where this image is stored.
      const key = `${APP.SPROUT_ITERATION}/${APP.POD_NUMBER}/${req.user._id}-${currentTimestamp}`;

      // Upload the image to Digital Ocean spaces.
      await ImageService.uploadImage({
        content: buffer,
        key,
        mimeType
      });

      // Once the image is uploaded successfully, we set the URL so that it
      // can be saved to the DB.
      profilePictureKey = key;

      // Also, if there was previously an image key that was on file, we should
      // do some "cleanup" and delete that.
      if (req.user.profilePictureKey) {
        await ImageService.deleteImage(req.user.profilePictureKey);
      }
    }

    const user: UserDocument = await User.findByIdAndUpdate(
      req.user._id,
      Utils.cleanObject({ ...req.body, profilePictureKey })
    );

    return user;
  }
}
