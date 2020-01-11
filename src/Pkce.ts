import { SHA256 } from 'crypto-js'
import * as base64 from 'crypto-js/enc-base64'
import * as randombytes from 'randombytes'

interface Pkce {

    challenge: string,
    verifier: string,
}

class PkceSource {

    randomBuffer(): Buffer {
        return randombytes(32)
    }

    create(): Pkce {

        let verifier = urlReplace(this.randomBuffer().toString('base64'))
        let challenge = urlReplace(SHA256(verifier).toString(base64))

        return {
            challenge: challenge,
            verifier: verifier,
        }
    }
}

function urlReplace(input: string) {
    return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export { Pkce, PkceSource }