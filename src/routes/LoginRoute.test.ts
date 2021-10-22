import { TEST_USER } from '../../jest.setup';
import AuthCode from '../models/AuthCode';
import TextService from '../services/TextService';
import TestUtils from '../utils/TestUtils';

/**
 * TODO: (7.04)
 * - Remove the ".skip" from the following function.
 * - Go to your terminal and run the following command:
 *        npm run test LoginRoute
 * - Delete this comment.
 */
describe('POST /login', () => {
  test('If the phone number is not valid, should return a 400.', async () => {
    await TestUtils.agent
      .post('/login')
      .send({ phoneNumber: 'abcdefghijkl' })
      .expect(400);
  });

  test('Should create a new auth code for the user and send a text to user.', async () => {
    TextService.sendText = jest.fn().mockResolvedValue(true);

    await TestUtils.agent
      .post('/login')
      .send({ phoneNumber: TEST_USER.phoneNumber })
      .expect(201)
      .then(async () => {
        expect(TextService.sendText).toBeCalled();

        const authCodes = await AuthCode.find({
          phoneNumber: TEST_USER.phoneNumber
        });

        // There should only be 1 auth code for a user ever.
        expect(authCodes).toHaveLength(1);
      });
  });

  test('If there was an error sending a text, should return a 500.', async () => {
    TextService.sendText = jest.fn().mockResolvedValue(false);

    await TestUtils.agent
      .post('/login')
      .send({ phoneNumber: TEST_USER.phoneNumber })
      .expect(500);
  });
});
