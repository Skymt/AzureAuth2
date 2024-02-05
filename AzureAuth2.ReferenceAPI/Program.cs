using AzureAuth2.Core;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddJWTAuthentication(builder.Configuration);

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
