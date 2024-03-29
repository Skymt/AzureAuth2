using AzureAuth2.Core;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSpoofableTimeProvider(out var timeProvider);
builder.Services.AddJWTAuthentication(builder.Configuration);

// Spoof the time to allow the tokens in the http files to be valid.
timeProvider.Spoof(new DateTime(2022, 1, 1));

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseStaticFiles();
app.MapControllers();

app.MapGet("/whoami", (HttpContext context) => context.User.Claims.Any()
    ? Results.Ok(context.User.Claims.Select(c => new { c.Type, c.Value }).ToArray())
    : Results.Ok(new { result = "You're nothing to me." }));

app.Run();
