import { Params, Secure, SecureImpl } from './Secure';

const create = (params: Params): Secure => new SecureImpl(params);

export { Secure, Params, create }
