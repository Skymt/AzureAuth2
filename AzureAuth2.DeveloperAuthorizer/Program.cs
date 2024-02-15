using AzureAuth2.Core;
using System.Security.Claims;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddJWTManager();
builder.Services.AddCors();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors(policy => policy.AllowAnyOrigin());
// Note: It is not recommended to allow any origin in a production environment! Restrict to known front-end origins.

app.MapGet("/auth/{name}", (string name, JWTManager jwtProvider) 
    => jwtProvider.Generate(claims: getClaimSet(name), duration: TimeSpan.FromDays(365)));
// Note: It is not recommended to use more than a few seconds duration for an auth token in a production environment!
// The exchange of the auth and session JWTs should be done automatically.

app.Run();

// Note: This base set will get additional claims from the conversion to a JWT.
static Claim[] getClaimSet(string name) =>
[
    new(ClaimTypes.Name, name),
    new(ClaimTypes.Role, "Developer"),
    new("CustomType", "CustomValue")
];