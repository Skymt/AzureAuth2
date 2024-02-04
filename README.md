# Azure Auth
Stores JWT claims in a table storage, and allows for refreshing short-lived JWTs using a long-lived http-only cookie.

## Setting up secrets

The developer authorizer has the JWT secret in the [settings file](AzureAuth2.DeveloperAuthorizer/appsettings.json) file.
This value should be handled better - for the other projects, you will need to add it
to your local secrets file, by right-clicking the Secrets.json file under Connected Services.

To avoid nesting a single value, you can add it with the following key: "JWT:Secret".

The SessionService also need a connection string to the Azure Table Storage. This should be added to the secrets file as well: "ConnectionStrings:ClaimsStorage": "UseDevelopmentStorage=true".

### HINT: USE AZURE KEY VAULT WHEN CREATING A PRODUCTION VERSION OF THIS PROJECT