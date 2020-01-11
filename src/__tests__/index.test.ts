import { create } from '../index';

test('create', () => {
  const result = create({
    clientId: 'test-client-id',
    issuer: 'test-issuer',
    scope: 'test-scope',
  });
  expect(result).not.toBeUndefined();
});
