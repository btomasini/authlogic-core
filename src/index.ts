import { Params, Secure, SecureImpl } from './Secure';

const create = (params: Params) => new SecureImpl(params);

export { Secure, Params, create }
