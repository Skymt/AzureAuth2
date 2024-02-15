using AzureAuth2.Core;
using System.Security.Claims;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSpoofableTimeProvider(out var timeProvider);
builder.Services.AddJWTManager();
builder.Services.AddCors();

var app = builder.Build();
// Spoof the time to allow the tokens in the http files to be valid.
timeProvider.Spoof(new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero));

// Configure the HTTP request pipeline.
app.UseCors(policy => policy.AllowAnyOrigin());
// Note: It is not recommended to allow any origin in a production environment! Restrict to known front-end origins.

app.MapGet("/auth/{name}", (string name, JWTManager jwtProvider) 
    => jwtProvider.Generate(claims: getClaimSet(name), duration: TimeSpan.FromSeconds(30)));

app.Run();

// Note: This base set will get additional claims from the conversion to a JWT.
static Claim[] getClaimSet(string name) =>
[
    new(ClaimTypes.Name, name),
    new(ClaimTypes.Role, "Developer"),
    new("CustomType", "CustomValue")
];