import { TEST_USER } from '../../jest.setup';
import AuthCode, { AuthCodeDocument } from '../models/AuthCode';
import TestUtils from '../utils/TestUtils';

describe('POST /verify', () => {
  test('If code is not a number, return a 400.', async () => {
    await TestUtils.agent.post('/verify').send({ code: '123456' }).expect(400);
  });

  test('If code not 6 digits, return a 400.', async () => {
    await TestUtils.agent.post('/verify').send({ code: 123456789 }).expect(400);
  });

  test('If phone number is not valid, return a 400.', async () => {
    await TestUtils.agent
      .post('/verify')
      .send({ code: 123456, phoneNumber: 'INVALID_PHONE_NUMBER' })
      .expect(400);
  });

  test('If no auth code is found, return a 404.', async () => {
    await TestUtils.agent
      .post('/verify')
      .send({ code: 123456, phoneNumber: TEST_USER.phoneNumber })
      .expect(404);
  });

  test('If the code is correct, delete the auth code and return a 201.', async () => {
    const authCode = await AuthCode.create({
      phoneNumber: TEST_USER.phoneNumber
    });

    await TestUtils.agent
      .post('/verify')
      .send({ code: authCode.value, phoneNumber: TEST_USER.phoneNumber })
      .expect(201)
      .then(async () => {
        const deletedAuthCode: AuthCodeDocument = await AuthCode.findById(
          authCode._id
        );

        expect(deletedAuthCode).toBeNull();
      });
  });
});
