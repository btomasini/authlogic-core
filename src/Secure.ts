import { Authentication } from './Authentication';
import { PkceSource, Pkce } from './Pkce';
import { Optional } from './Lang';
import * as queryString from 'query-string';
import axios from 'axios';

interface Params {
  issuer: string;
  clientId: string;
  scope: string;
}

/*
TODO - Can use 
interface TokenResponse {
    token_type: string,
    expires_in: number,
    access_token: string,
    id_token: string,
    refresh_token: string
}

interface ErrorResponse {
    error: string,
    error_description: number,
}
*/

interface Storage {
  pkce: Pkce;
  state: string;
  nonce: string;
}

interface Secure {
  secure(): void;
}

const storageKey = 'authlogic.storage';

const codeKey = 'code';
const stateKey = 'state';
const errorCategoryKey = 'error';
const errorDescriptionKey = 'error_description';

const randomStringDefault = (length: number): string => {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};

const getQueryDefault = (): string => location.search;

class SecureImpl implements Secure {
  private params: Params;
  private pkceSource: PkceSource;
  private authentication?: Authentication;

  // Visible for testing
  randomString: (length: number) => string = randomStringDefault;
  // Visible for testing
  getQuery: () => string = getQueryDefault;

  constructor(params: Params, pkceSource: PkceSource) {
    this.pkceSource = pkceSource;
    this.params = params;
  }

  async secure() {
    const q = queryString.parse(this.getQuery());
    const code = this.stringFromQuery(q, codeKey);
    const state = this.stringFromQuery(q, stateKey);
    const errorCategory = this.stringFromQuery(q, errorCategoryKey);
    const errorDescription = this.stringFromQuery(q, errorDescriptionKey) || '';
    if (errorCategory) {
      this.authentication = undefined;
      throw new Error(`[${errorCategory}] ${errorDescription}`);
    }
    if (code) {
      await this.loadFromCode(code, state);
      return;
    }
    let storage = await this.createAndStoreStorage();
    await this.redirect(storage);
  }

  private stringFromQuery(q: queryString.ParsedQuery<string>, name: string): string | undefined {
    const raw = q[name];
    if (typeof raw == 'string') {
      return raw;
    }
    return undefined;
  }

  async loadFromCode(code: string, state: string | undefined) {
    const storage = await this.getStorage();
    if (!storage) {
      throw new Error('Nothing in storage');
    }

    const res = await axios.post(
      this.params.issuer + '/oauth/token',
      queryString.stringify({
        grant_type: 'authorization_code',
        code: code,
        code_verifier: storage.pkce.verifier,
      }),
      {
        adapter: require('axios/lib/adapters/xhr'),
        headers: { 'Content-Type': 'multipart/form-data' },
      },
    );

    const resp = JSON.parse(res.data);

    if (resp.error) {
      this.authentication = undefined;
      throw new Error(`[${resp.error}] ${resp.error_description}`);
    }

    if (resp.access_token) {
      this.authentication = {
        accessToken: resp.access_token,
        idToken: resp.id_token,
        refreshToken: resp.refresh_token,
        expiresIn: resp.expires_in,
      };
    }
  }

  private async redirect(storage: Storage) {
    let p = this.params;
    let redirectUri = window.location.href;
    window.location.assign(
      `${this.params.issuer}/authorize?client_id=${p.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${
        storage.state
      }&nonce=${storage.nonce}&response_type=code`,
    );
  }

  async getAuthentication(): Promise<Optional<Authentication>> {
    return this.authentication;
  }

  private async getStorage(): Promise<Optional<Storage>> {
    const raw = sessionStorage.getItem(storageKey);
    if (raw == null) {
      return undefined;
    }
    return JSON.parse(raw);
  }

  private async createAndStoreStorage(): Promise<Storage> {
    const storage: Storage = {
      pkce: this.pkceSource.create(),
      state: this.randomString(32),
      nonce: this.randomString(32),
    };
    sessionStorage.setItem(storageKey, JSON.stringify(storage));
    return storage;
  }
}

export { Params, Secure, SecureImpl, randomStringDefault };
