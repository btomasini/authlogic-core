import { Params, Secure, SecureImpl } from './Secure';
import { PkceSource } from './Pkce';

const create = (params: Params): Secure => new SecureImpl(params, new PkceSource());

export { Secure, Params, create };
