import { TEST_AUTH_COOKIE, TEST_USER } from '../../jest.setup';
import TestUtils from '../utils/TestUtils';

/**
 * TODO: (10.03)
 * - Remove the ".skip" from the following function.
 * - Go to your terminal and run the following command:
 *        npm run test GetMe
 * - Delete this comment.
 */
describe('GET /me', () => {
  test('If the user is not authenticated, should return a 401.', async () => {
    await TestUtils.agent.get('/me').expect(401);
  });

  test('If the user is authenticated, returns the logged-in user.', async () => {
    await TestUtils.agent
      .get('/me')
      .set('Cookie', TEST_AUTH_COOKIE)
      .expect(200)
      .then(({ body }) => {
        expect(body._id).toEqual(TEST_USER._id.toString());
      });
  });
});
