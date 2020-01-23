import { Substitute, SubstituteOf } from '@fluffy-spoon/substitute';
import axios from 'axios';
import 'jest-localstorage-mock';
import * as queryString from 'query-string';
import { Optional } from '../Lang';
import { PkceSource } from '../Pkce';
import { IParams, IUserinfo, randomStringDefault, SecureImpl } from '../Secure';

jest.mock('axios');
const mockAxios = axios as jest.Mocked<typeof axios>;

const pushStateMock = jest.fn();

beforeAll(() => {
  history.pushState = pushStateMock;
  jest.useFakeTimers()
})

beforeEach(() => {
  pushStateMock.mockReset();
  sessionStorage.clear();
});

describe('randomStringDefault', () => {
  it('generates correct random values', () => {
    const results = new Map<string, boolean>();
    const iterations = 1000;
    for (let i = 0; i < iterations; i++) {
      let s = randomStringDefault(32);
      expect(s).toMatch(/^[A-Za-z0-9]{32}$/);
      results.set(s, true);
    }
    expect(results.size).toBe(iterations);
  });
});

describe('SecureImpl', () => {
  const storageFlowKey = 'authlogic.storage.flow';
  const storageAuthKey = 'authlogic.storage.auth';
  const storageUserinfoKey = 'authlogic.storage.userinfo';

  const errorCategory = 'test-error';
  const errorDescription = 'test-error-description';

  const issuer = 'test-issuer';
  const clientId = 'test-client-id';
  const scope = 'test-scope';

  const verifier = 'test-verifier';
  const challenge = 'test-challenge';
  const code = 'test-code';
  const state = 'test-state';
  const nonce = 'test-nonce';

  let query = '';

  const thisUri = 'http://test-uri';
  const refreshToken = 'test-refresh-token';
  const idToken = 'test-id-token';
  const expiresIn = 7200;
  const accessToken = 'test-access-token';
  const accessToken2 = 'test-access-token-2';

  const sub = 'test-sub'
  const lastName = 'test-lastname'

  const authentication = {
    accessToken,
    expiresIn,
    idToken,
    refreshToken,
  };

  const authentication2 = {
    accessToken: accessToken2,
    expiresIn,
    idToken,
    refreshToken,
  };

  const userinfo: IUserinfo = {
    lastName, sub
  }

  let pkceSource: SubstituteOf<PkceSource>;

  let unit: SecureImpl;
  let error: Optional<Error>;

  const params = (): IParams => {
    return {
      clientId,
      issuer,
      scope,
    };
  };

  const makeUnit = (): SecureImpl => {
    const $unit = new SecureImpl(pkceSource);
    $unit.randomString = (length: number) => `stub-${length}`;
    $unit.getQuery = () => query;
    $unit.refreshLimit = 3
    return $unit;
  };

  let redirectTo: string;

  beforeEach(async () => {
    redirectTo = '';
    query = '';
    error = undefined;
    pkceSource = Substitute.for<PkceSource>();
    window.location.assign = jest.fn(value => {
      redirectTo = value;
    });
    sessionStorage.removeItem(storageFlowKey);
    unit = makeUnit();
  });

  describe('initial', () => {
    describe('no secure call', () => {
      it('has no authentication', () => {
        expect(unit.getAuthentication()).toBeUndefined();
      });
      it('has no userinfo', () => {
        expect(unit.getUserinfo()).toBeUndefined();
      });
      it('has no session storage', () => {
        expect(sessionStorage.__STORE__).toEqual({});
      });
      it('does not push state', () => {
        expect(pushStateMock.mock.calls.length).toBe(0);
      });
      it('secure throws excepiton', async () => {
        try {
          await unit.secure();
          fail('Error should have been thrown');
        } catch (e) {
          expect(e.message).toBe('Params not set, please call init first.');
        }
      });
    });

    describe('after init', () => {
      beforeEach(() => {
        unit.init(params());
      });

      it('has no authentication', () => {
        expect(unit.getAuthentication()).toBeUndefined();
      });
      it('has no userinfo', () => {
        expect(unit.getUserinfo()).toBeUndefined();
      });
      it('has no session storage', () => {
        expect(sessionStorage.__STORE__).toEqual({});
      });
      it('does not push state', () => {
        expect(pushStateMock.mock.calls.length).toBe(0);
      });

      describe('secure', () => {

        describe('authentication and userinfo already in storage', () => {
          beforeEach(async () => {
            sessionStorage.__STORE__[storageAuthKey] = JSON.stringify(authentication);
            sessionStorage.__STORE__[storageUserinfoKey] = JSON.stringify(userinfo);
            expect(unit.getAuthentication()).toBeUndefined();
            await unit.secure();
          });
          it('loads authentication from the session store', () => {
            expect(unit.getAuthentication()).toEqual(authentication);
          });
          it('loads userinfo from the session store', () => {
            expect(unit.getUserinfo()).toEqual(userinfo);
          });
          it('does not push state', () => {
            expect(pushStateMock.mock.calls.length).toBe(0);
          });
          it('does not have flow storage', () => {
            expect(sessionStorage.__STORE__[storageFlowKey]).toBeUndefined();
          });
        });

        describe('authentication not in storage', () => {
          beforeEach(async () => {
            pkceSource.create().returns({
              challenge,
              verifier,
            });
            await unit.secure();
          });
          it('has no authentication', async () => {
            expect(unit.getAuthentication()).toBeUndefined();
          });
          it('has no userinfo', async () => {
            expect(unit.getUserinfo()).toBeUndefined();
          });
          it('redirected to the endpoint', () => {
            expect(redirectTo).toBe(
              `test-issuer/authorize?client_id=test-client-id&redirect_uri=${encodeURIComponent(
                window.location.href,
              )}&state=stub-32&nonce=stub-32&response_type=code&scope=test-scope&code_challenge=test-challenge`,
            );
          });
          it('stores state and nonce', () => {
            expect(JSON.parse(sessionStorage.__STORE__[storageFlowKey])).toEqual({
              nonce: 'stub-32',
              pkce: {
                challenge,
                verifier,
              },
              state: 'stub-32',
              thisUri: window.location.href,
            });
          });
          it('does not push state', () => {
            expect(pushStateMock.mock.calls.length).toBe(0);
          });
          it('does not have auth storage', () => {
            expect(sessionStorage.__STORE__[storageAuthKey]).toBeUndefined();
          });
          it('does not have userionfo storage', () => {
            expect(sessionStorage.__STORE__[storageUserinfoKey]).toBeUndefined();
          });
        });

        describe('return with code without storage', () => {
          beforeEach(async () => {
            query = `?code=${code}`;
            try {
              await unit.secure();
            } catch (e) {
              error = e
            }
          });
          it('throws and error', () => {
            expect(error).toEqual(new Error('Nothing in storage'));
          });
          it('does not push state', () => {
            expect(pushStateMock.mock.calls.length).toBe(0);
          });
          it('does not have auth storage', () => {
            expect(sessionStorage.__STORE__[storageAuthKey]).toBeUndefined();
          });
          it('does not have userinfo storage', () => {
            expect(sessionStorage.__STORE__[storageUserinfoKey]).toBeUndefined();
          });
        });

        describe('return with oauth error message', () => {
          beforeEach(async () => {
            query = `?error=${errorCategory}&error_description=${errorDescription}`;
            sessionStorage.__STORE__[storageFlowKey] = JSON.stringify({
              thisUri,
            });
            try {
              await unit.secure();
            } catch (e) {
              error = e;
            }
          });
          it('throws an error', () => {
            expect(error).toEqual(new Error(`[${errorCategory}] ${errorDescription}`));
          });
          it('pushes state after error', () => {
            expect(pushStateMock.mock.calls.length).toBe(1);
            expect(pushStateMock.mock.calls[0][2]).toBe(thisUri);
          });
          it('does not have auth storage', () => {
            expect(sessionStorage.__STORE__[storageAuthKey]).toBeUndefined();
          });
          it('does not have userinfo storage', () => {
            expect(sessionStorage.__STORE__[storageUserinfoKey]).toBeUndefined();
          });
        });

        describe('return with code and storage', () => {

          beforeEach(async () => {
            query = `?code=${code}`;
            sessionStorage.__STORE__[storageFlowKey] = JSON.stringify({
              nonce,
              pkce: {
                challenge,
                verifier,
              },
              state,
              thisUri,
            });
          });

          describe('server error', () => {
            beforeEach(async () => {
              const err = new Error('Host cannot be reached');
              try {
                mockAxios.post.mockRejectedValue(err);
                await unit.secure();
                fail('Expected exception');
              } catch (e) {
                expect(e).toEqual(err);
              }
            });
            it('makes call to token endpoint', async () => {
              expect(mockAxios.post).toHaveBeenCalledWith(
                issuer + '/oauth/token',
                queryString.stringify({
                  code,
                  code_verifier: verifier,
                  grant_type: 'authorization_code',
                }),
                {
                  adapter: require('axios/lib/adapters/xhr'),
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                },
              );
            });
            it('does not push state', () => {
              expect(pushStateMock.mock.calls.length).toBe(0);
            });
            it('does not have auth storage', () => {
              expect(sessionStorage.__STORE__[storageAuthKey]).toBeUndefined();
            });
            it('does not have userinfo storage', () => {
              expect(sessionStorage.__STORE__[storageUserinfoKey]).toBeUndefined();
            });
          });

          describe('oauth error', () => {
            beforeEach(async () => {
              mockAxios.post.mockResolvedValue({
                data: {
                  error: errorCategory,
                  error_description: errorDescription,
                },
              });
              try {
                await unit.secure();
              } catch (e) {
                error = e;
              }
            });
            it('throws an error', () => {
              expect(error).toEqual(new Error(`[${errorCategory}] ${errorDescription}`));
            });
            it('sets authentication to undefined', async () => {
              expect(await unit.getAuthentication()).toBeUndefined();
            });
            it('makes call to token endpoint', async () => {
              expect(mockAxios.post).toHaveBeenCalledWith(
                issuer + '/oauth/token',
                queryString.stringify({
                  code,
                  code_verifier: verifier,
                  grant_type: 'authorization_code',
                }),
                {
                  adapter: require('axios/lib/adapters/xhr'),
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                },
              );
            });
            it('pushes state after error', () => {
              expect(pushStateMock.mock.calls.length).toBe(1);
              expect(pushStateMock.mock.calls[0][2]).toBe(thisUri);
            });
            it('does not have auth storage', () => {
              expect(sessionStorage.__STORE__[storageAuthKey]).toBeUndefined();
            });
            it('does not have userinfo storage', () => {
              expect(sessionStorage.__STORE__[storageUserinfoKey]).toBeUndefined();
            });
          });
          describe('success', () => {
            beforeEach(async () => {
              mockAxios.post.mockResolvedValue({
                data: {
                  access_token: accessToken,
                  id_token: idToken,
                  expires_in: expiresIn,
                  refresh_token: refreshToken,
                  token_type: 'bearer',
                },
              });
              mockAxios.get.mockResolvedValue({
                data: userinfo,
              });
              try {
                await unit.secure();
              } catch (e) {
                error = e;
              }
            });
            it('does not throw an error', () => {
              expect(error).toBeUndefined();
            });
            it('sets authentication', async () => {
              expect(unit.getAuthentication()).toEqual(authentication);
            });
            it('sets userinfo', async () => {
              expect(unit.getUserinfo()).toEqual(userinfo);
            });
            it('makes call to token endpoint', async () => {
              expect(mockAxios.post).toHaveBeenCalledWith(
                issuer + '/oauth/token',
                queryString.stringify({
                  code,
                  code_verifier: verifier,
                  grant_type: 'authorization_code',
                }),
                {
                  adapter: require('axios/lib/adapters/xhr'),
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                },
              );
            });
            it('makes call to userinfo endpoint', async () => {
              expect(mockAxios.get).toHaveBeenCalledWith(
                issuer + '/userinfo',
                {
                  headers: { 'Authorization': 'Bearer ' + accessToken },
                },
              );
            });
            it('pushes state to stored uri', () => {
              expect(pushStateMock.mock.calls.length).toBe(1);
              expect(pushStateMock.mock.calls[0][2]).toBe(thisUri);
            });
            it('removes storage', () => {
              expect(sessionStorage.__STORE__[storageFlowKey]).toBeUndefined();
            });
            it('sets authentication to storage', () => {
              expect(sessionStorage.__STORE__[storageAuthKey]).toEqual(JSON.stringify(authentication));
            });
            it('sets userinfo to storage', () => {
              expect(sessionStorage.__STORE__[storageUserinfoKey]).toEqual(JSON.stringify(userinfo));
            });

            describe('successful refresh', () => {

              beforeEach(() => {
                mockAxios.post.mockReset()
                mockAxios.get.mockReset()
                pushStateMock.mockReset();
                mockAxios.post.mockResolvedValue({
                  data: {
                    access_token: accessToken2,
                    id_token: idToken,
                    expires_in: expiresIn,
                    refresh_token: refreshToken,
                    token_type: 'bearer',
                  },
                });
                try {
                  jest.runAllTimers()
                } catch (e) {
                  error = e;
                }
              })

              it('does not throw an error', () => {
                expect(error).toBeUndefined();
              });
              it('sets new authentication', async () => {
                expect(unit.getAuthentication()).toEqual(authentication2);
              });
              it('leaves userinfo unchanged', async () => {
                expect(unit.getUserinfo()).toEqual(userinfo);
              });
              it('makes call to token endpoint', async () => {
                expect(mockAxios.post).toHaveBeenCalledWith(
                  issuer + '/oauth/token',
                  queryString.stringify({
                    refresh_token: refreshToken,
                    grant_type: 'refresh_token',
                  }),
                  {
                    adapter: require('axios/lib/adapters/xhr'),
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  },
                );
              });
              it('does not make call to userinfo endpoint', async () => {
                expect(mockAxios.get).not.toHaveBeenCalled()
              });
              it('does not pushe state', () => {
                expect(pushStateMock.mock.calls.length).toBe(0);
              });
              it('removes storage', () => {
                expect(sessionStorage.__STORE__[storageFlowKey]).toBeUndefined();
              });
              it('sets authentication in storage', () => {
                expect(sessionStorage.__STORE__[storageAuthKey]).toEqual(JSON.stringify(authentication2));
              });
              it('leaves userinfo to storage', () => {
                expect(sessionStorage.__STORE__[storageUserinfoKey]).toEqual(JSON.stringify(userinfo));
              });
            });
          });
        });
      });
    });
  });
});
