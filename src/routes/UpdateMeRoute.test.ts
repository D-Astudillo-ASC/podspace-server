import { TEST_AUTH_COOKIE, TEST_USER } from '../../jest.setup';
import User, { UserDocument } from '../models/User';
import TestUtils from '../utils/TestUtils';

describe('PATCH /me', () => {
  test('If the user is not authenticated, should return a 401.', async () => {
    await TestUtils.agent.patch('/me').expect(401);
  });

  test('If the first name is defined, must be at least 1 character.', async () => {
    await TestUtils.agent
      .patch('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .send({ firstName: '' })
      .expect(400);
  });

  test('If the last name is defined, must be at least 1 character.', async () => {
    await TestUtils.agent
      .patch('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .send({ lastName: '' })
      .expect(400);
  });

  test('If the Instagram URL is defined, must be a valid URL.', async () => {
    await TestUtils.agent
      .patch('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .send({ instagramUrl: 'Hello World!' })
      .expect(400);
  });

  test('If the LinkedIn URL is defined, must be a valid URL.', async () => {
    await TestUtils.agent
      .patch('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .send({ linkedInUrl: 'Hello World!' })
      .expect(400);
  });

  test('If the Twitter URL is defined, must be a valid URL.', async () => {
    await TestUtils.agent
      .patch('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .send({ twitterUrl: 'Hello World!' })
      .expect(400);
  });

  test('Should update the user with the defined body.', async () => {
    const body: Partial<UserDocument> = {
      firstName: 'Rami',
      instagramUrl: 'https://www.instagram.com',
      lastName: 'Abdou',
      linkedInUrl: 'https://www.linkedin.com',
      twitterUrl: 'https://www.twitter.com'
    };

    await TestUtils.agent
      .patch('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .send(body)
      .expect(200)
      .then(async () => {
        const user = await User.findById(TEST_USER._id);

        expect(user.firstName).toBe(body.firstName);
        expect(user.instagramUrl).toBe(body.instagramUrl);
        expect(user.lastName).toBe(body.lastName);
        expect(user.linkedInUrl).toBe(body.linkedInUrl);
        expect(user.twitterUrl).toBe(body.twitterUrl);
      });
  });
});
