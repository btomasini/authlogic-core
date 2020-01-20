import { create } from '../index';

test('create', () => {
  const result = create();
  expect(result).not.toBeUndefined();
});
