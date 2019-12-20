import { create, Secure } from '../index';

test('create', () => {
    let result = create({ clientId: 'test' })
    expect(result).not.toBeUndefined();
});
