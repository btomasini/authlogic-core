import { SHA256 } from 'crypto-js';
import * as base64 from 'crypto-js/enc-base64';
import * as randombytes from 'randombytes';

interface IPkce {
  challenge: string;
  verifier: string;
}

class PkceSource {
  public randomBuffer(): Buffer {
    return randombytes(32);
  }

  public create(): IPkce {
    const verifier = urlReplace(this.randomBuffer().toString('base64'));
    const challenge = urlReplace(SHA256(verifier).toString(base64));

    return {
      challenge,
      verifier,
    };
  }
}

function urlReplace(input: string) {
  return input
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export { IPkce, PkceSource };
