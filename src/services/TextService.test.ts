import { APP } from '../utils/constants';
import TextService, { client } from './TextService';

/**
 * TODO: (6.05)
 * - Remove the ".skip" from the following function.
 * - Go to your terminal and run the following command:
 *        npm run test TextService
 * - Delete this comment.
 */
describe('TextService.sendText()', () => {
  // Mock the twilio "sending" functionality.
  client.messages.create = jest.fn();

  afterEach(() => {
    // As a fail safe, ensure that this is set back to false (for one of the)
    // tests we need this to be true, but we don't want all tests like this!
    APP.IS_PRODUCTION = false;
  });

  test('If the environment IS NOT production, should not call the Twilio API.', async () => {
    const success: boolean = await TextService.sendText({
      message: '',
      to: ''
    });

    expect(success).toBe(true);
    expect(client.messages.create).not.toBeCalled();
  });

  test('Should call the Twilio API if there is no error, should return true.', async () => {
    // This has to be true in order for client.messages.create to be called...
    APP.IS_PRODUCTION = true;

    const success: boolean = await TextService.sendText({
      message: '',
      to: ''
    });

    expect(client.messages.create).toBeCalled();
    expect(success).toBe(true);
  });

  test('If the text failed to send, should return false.', async () => {
    // This has to be true in order for client.messages.create to be called...
    APP.IS_PRODUCTION = true;

    client.messages.create = jest.fn().mockRejectedValue(false);

    const success: boolean = await TextService.sendText({
      message: '',
      to: ''
    });

    expect(client.messages.create).toBeCalled();
    expect(success).toBe(false);
  });
});
