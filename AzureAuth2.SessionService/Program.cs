using AzureAuth2.Core;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddCors();
builder.Services.AddHttpContextAccessor();

builder.Services.AddSpoofableTimeProvider(out var timeProvider);
builder.Services.AddJWTManager();
builder.Services.AddSingleton<ClaimsTableRepository>();
builder.Services.AddTransient<AuthenticationHandler>();

var app = builder.Build();

// Spoof the time to allow the tokens in the http files to be valid.
timeProvider.Spoof(new DateTime(2022, 1, 1));

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();
app.UseCors(policy => policy
    .WithOrigins("https://localhost:7046")  // Frontend is hosted by AzureAuth2.ReferenceAPI (i.e index.html has some javascript)
    .WithMethods("PATCH")                   // PATCH is used for both login and logout
    .WithHeaders("Authorization")           // JWTs from authorizers are sent in the Authorization header
    .AllowCredentials()                     // http-only cookies are used for refresh tokens
);

app.MapPatch("/login", async (AuthenticationHandler handler) =>
{
    var claims = await handler.GetClaimsFromAuthJWT();
    claims ??= await handler.GetClaimsFromStorage();

    if (claims == null)
    {
        await handler.DropClaims();
        return Results.Unauthorized();
    }

    var (token, refreshHint) = await handler.StoreClaims(claims);
    return Results.Ok(new { token, refreshHint });
});

app.MapPatch("/logout", async (AuthenticationHandler handler) =>
{
    await handler.DropClaims();
    return Results.Ok();
});

app.Run();