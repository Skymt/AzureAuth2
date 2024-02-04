class JWTClient {
    #sessionService; #token; #refresh;
    constructor(sessionService) {
        this.#sessionService = sessionService;
    }

    async login(authJWT) {
        let fetchOptions = { credentials: "include", method: "PATCH" };
        if (authJWT) fetchOptions.headers = { Authorization: `Bearer ${authJWT}` }

        return await fetch(`${this.#sessionService}/login`, fetchOptions)
            .then(r => r.json()).then(jwt => this.#jwt = jwt)
            .then(_ => true).catch(_ => false);
    }
    async logout() {
        await fetch(`${this.#sessionService}/logout`, { credentials: "include", method: "PATCH" });
        this.#token = null;
    }
    async fetch(endpoint, options) {
        if (!this.authorized) throw new Error('JWTClient is unauthorized!');

        const auth = "Authorization";
        options ||= {}; options.headers ||= {};
        options.headers[auth] = `Bearer ${this.#token}`;

        return await fetch(endpoint, options);
    }

    get authorized() { return !!this.#token; }
    get claims() { if (this.authorized) return JSON.parse(atob(this.#token.split('.')[1])); }
    set #jwt(jwt) {
        this.#token = jwt.token;
        if (this.#refresh) clearTimeout(this.#refresh);
        this.#refresh = setTimeout(async _ => await this.login(), jwt.refreshAt);
    }
}