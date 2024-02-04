using AzureAuth2.Core;
using System.Security.Claims;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddJWTManager();
builder.Services.AddCors();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors(policy => policy.AllowAnyOrigin());

app.MapGet("/token/{name}", (string name, JWTManager jwtProvider) 
    => jwtProvider.Generate(claims: getClaimSet(name), duration: TimeSpan.FromDays(365)));
app.Run();

// Generate the default claim set
static Claim[] getClaimSet(string name) => new Claim[]
{
    new(ClaimTypes.Name, name),
    new(ClaimTypes.Role, "Developer")
};