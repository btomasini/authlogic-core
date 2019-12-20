import Authentication from "./Authentication";
import { Optional } from './Lang'

interface Params {
    issuer: string
    clientId: string
    grantType: string
}

interface Secure {

}

class SecureImpl implements Secure {

    private params: Params
    private authentication?: Authentication

    constructor(params: Params) {
        this.params = params
    }

    async secure() {
        if (!this.authentication) {
            await this.redirect();
        }
    }

    private async redirect() {
        window.location.assign(`${this.params.issuer}/authorize?client_id=${this.params.clientId}`)
    }

    async getAuthentication(): Promise<Optional<Authentication>> {
        return await this.authentication;
    }
}

export { Params, Secure, SecureImpl };