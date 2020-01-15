import { Authentication } from './Authentication';
import { PkceSource } from './Pkce';
import { IParams, ISecure, SecureImpl } from './Secure';

const create = (): ISecure => new SecureImpl(new PkceSource());

export { Authentication, ISecure, IParams, create };
