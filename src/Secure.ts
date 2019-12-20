import Authentication from "./Authentication";
import { Optional } from './Lang'

interface Params {
    issuer: string
    clientId: string
    grantType: string
    scope: string
    responseType: string
}

interface Storage {
    state: string
    nonce: string
}


interface Secure {
    secure(): void
}

const storageKey = "authlogic.storage";

class SecureImpl implements Secure {

    private params: Params
    private authentication?: Authentication

    constructor(params: Params) {
        this.params = params
    }

    async secure() {
        if (!this.authentication) {
            let storage = await this.createAndStoreStorage();
            await this.redirect(storage);
        }
    }

    private async redirect(storage: Storage) {
        let p = this.params;
        let redirectUri = window.location.href;
        window.location.assign(`${this.params.issuer}/authorize?client_id=${p.clientId}&redirect_uri=${redirectUri}&state=${storage.state}&nonce=${storage.nonce}&response_type=${p.responseType}`);
    }

    async getAuthentication(): Promise<Optional<Authentication>> {
        return await this.authentication;
    }

    private async createAndStoreStorage(): Promise<Storage> {
        let storage = {
            state: "state",
            nonce: "state"
        }
        sessionStorage.setItem(storageKey, JSON.stringify(storage));
        return storage;
    }
}

export { Params, Secure, SecureImpl };