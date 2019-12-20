import { Params, Secure, SecureImpl } from './Secure';

export const create = (params: Params) => new SecureImpl(params);

export { Secure }
