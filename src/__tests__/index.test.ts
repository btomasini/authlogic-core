import { create } from '../index';

test('create', () => {
  let result = create({
    issuer: 'test-issuer',
    clientId: 'test-client-id',
    scope: 'test-scope',
  });
  expect(result).not.toBeUndefined();
});
