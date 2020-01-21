import axios from 'axios';
import * as queryString from 'query-string';
import { Authentication } from './Authentication';
import { Optional } from './Lang';
import { IPkce, PkceSource } from './Pkce';

interface IParams {
  issuer: string;
  clientId: string;
  scope: string;
}

interface IStorage {
  thisUri: string;
  nonce: string;
  pkce: IPkce;
  state: string;
}

interface IUserinfo {
  sub: string;
  [x: string]: any;
}

interface ISecure {
  init(params: IParams): void;
  secure(): Promise<void>;
  getUserinfo(): Promise<IUserinfo>;
  getAuthentication(): Optional<Authentication>;
}

const storageFlowKey = 'authlogic.storage.flow';
const storageAuthKey = 'authlogic.storage.auth';

const codeKey = 'code';
const stateKey = 'state';
const errorCategoryKey = 'error';
const errorDescriptionKey = 'error_description';

const randomStringDefault = (length: number): string => {
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};

const getQueryDefault = (): string => location.search;

class SecureImpl implements ISecure {
  // Visible for testing
  public randomString: (length: number) => string = randomStringDefault;

  // Visible for testing
  public getQuery: () => string = getQueryDefault;

  private params?: IParams;
  private pkceSource: PkceSource;
  private authentication?: Authentication;
  private userinfo?: IUserinfo;

  constructor(pkceSource: PkceSource) {
    this.pkceSource = pkceSource;
  }

  public init(params: IParams) {
    this.params = params;
  }

  public getAuthentication(): Optional<Authentication> {
    return this.authentication;
  }

  public async getUserinfo(): Promise<IUserinfo> {
    if (this.userinfo) {
      return Promise.resolve(this.userinfo);
    }

    if (!this.authentication) {
      throw new Error('Not authenticated');
    }

    const resp = await axios.get(this.params!.issuer + '/userinfo', {
      headers: {
        Authorization: 'Bearer ' + this.authentication.accessToken,
      },
    });

    this.userinfo = resp.data;
    return this.userinfo!;
  }

  public async secure() {
    this.assertInit();

    if (await this.loadFromStorage()) {
      return;
    }

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

    const storage = await this.createAndStoreStorage();
    await this.redirect(storage);
  }

  private assertInit() {
    if (!this.params) {
      throw new Error('Params not set, please call init first.');
    }
  }

  private stringFromQuery(q: queryString.ParsedQuery<string>, name: string): string | undefined {
    const raw = q[name];
    if (typeof raw === 'string') {
      return raw;
    }
    return undefined;
  }

  private async loadFromCode(code: string, state: string | undefined) {
    const storage = await this.getStorage();
    if (!storage) {
      throw new Error('Nothing in storage');
    }

    const res = await axios.post(
      this.params!.issuer + '/oauth/token',
      queryString.stringify({
        code,
        code_verifier: storage.pkce.verifier,
        grant_type: 'authorization_code',
      }),
      {
        adapter: require('axios/lib/adapters/xhr'),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      },
    );

    const resp = res.data;

    if (resp.error) {
      this.authentication = undefined;
      throw new Error(`[${resp.error}] ${resp.error_description}`);
    }

    if (resp.access_token) {
      this.authentication = {
        accessToken: resp.access_token,
        expiresIn: resp.expires_in,
        idToken: resp.id_token,
        refreshToken: resp.refresh_token,
      };
      await this.finalStorage(this.authentication);
      window.history.pushState('page', '', storage.thisUri);
    }
  }

  private async redirect(storage: IStorage) {
    const p = this.params!;
    window.location.assign(
      `${this.params!.issuer}/authorize?client_id=${p.clientId}&redirect_uri=${encodeURIComponent(
        storage.thisUri,
      )}&state=${storage.state}&nonce=${storage.nonce}&response_type=code&scope=${encodeURIComponent(
        p.scope,
      )}&code_challenge=${encodeURIComponent(storage.pkce.challenge)}`,
    );
  }

  private async getStorage(): Promise<Optional<IStorage>> {
    const raw = sessionStorage.getItem(storageFlowKey);
    if (raw == null) {
      return undefined;
    }
    return JSON.parse(raw);
  }

  private async createAndStoreStorage(): Promise<IStorage> {
    const storage: IStorage = {
      nonce: this.randomString(32),
      pkce: this.pkceSource.create(),
      state: this.randomString(32),
      thisUri: window.location.href,
    };
    sessionStorage.setItem(storageFlowKey, JSON.stringify(storage));
    return storage;
  }

  private async finalStorage(authentication: Authentication) {
    sessionStorage.setItem(storageAuthKey, JSON.stringify(authentication));
    sessionStorage.removeItem(storageFlowKey);
  }

  private async loadFromStorage(): Promise<boolean> {
    const authString = sessionStorage.getItem(storageAuthKey);
    if (authString) {
      this.authentication = JSON.parse(authString);
      return true;
    } else {
      return false;
    }
  }
}

export { IParams, ISecure, IUserinfo, SecureImpl, randomStringDefault };
