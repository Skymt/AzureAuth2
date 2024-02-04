# Azure Auth
Stores [JWT](https://jwt.io) claims in a table storage, and allows for refreshing short-lived JWTs using a long-lived http-only cookie.
This solution is intended to showcase proper handling of credentials in a web-application driven by microservices.
I.e. it cooperates with a browser to store the JWT and refresh token as securely as possible.
* It leverages both CORS and secure http-only cookies to protect the refresh token against [XSS](https://owasp.org/www-community/attacks/xss/) and [session hijacking](https://en.wikipedia.org/wiki/Session_hijacking).
* The provided [javascript client](AzureAuth2.ReferenceAPI/wwwroot/JWTClient.js) also uses [private properties](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes/Private_properties) to protect the JWT itself.
* [JWTManager](AzureAuth2.Core/JWTManager.cs) supports encrypted claims in case they contain [PII](https://www.investopedia.com/terms/p/personally-identifiable-information-pii.asp).


## Setting up secrets

The developer authorizer has the JWT secret used in the project in its [settings file](AzureAuth2.DeveloperAuthorizer/appsettings.json).
This is of course no good - for the other projects, you will need to add it to your local secrets file, by right-clicking the Secrets.json file under Connected Services in the solution explorer.

It is also good practice to keep connection strings in the secrets file, so SessionService will need that added as well:
```
secrets.json
{
  "ConnectionStrings:ClaimsStorage": "UseDevelopmentStorage=true", 
  "JWT:Secret": "USE KEYVAULT!V8wgKZ9YkHNd/tdUa0FreJTegYlaozQkslrBhN1jugK0j+eqlSCSz8TFg4XxFN45/mj7fvAI"
}
```

### HINT: USE AZURE KEY VAULT WHEN CREATING A PRODUCTION VERSION OF THIS PROJECT

## Running the project
There are several URLs hardcoded in the project, so you will need to run the following profiles:
* DeveloperAuthorizer: http
* SessionService: https
* ReferenceAPI: https


