using AzureAuth2.Core;
using System.Security.Claims;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddJWTManager(new SpoofableTimeProvider(new DateTime(2022, 1, 1)));
// Spoofed time to allow the tokens in the http files to be valid.
builder.Services.AddCors();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors(policy => policy.AllowAnyOrigin());

app.MapGet("/auth/{name}", (string name, JWTManager jwtProvider) 
    => jwtProvider.Generate(claims: getClaimSet(name), duration: TimeSpan.FromSeconds(30)));

app.Run();

// Note: This base set will get additional claims from the JWT generation.
static Claim[] getClaimSet(string name) =>
[
    new(ClaimTypes.Name, name),
    new(ClaimTypes.Role, "Developer"),
    new("CustomType", "CustomValue")
];