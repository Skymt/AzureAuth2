using AzureAuth2.Core;
using System.Security.Claims;

internal class AuthenticationHandler
{
    static readonly TimeSpan jwtLifetime = TimeSpan.FromMinutes(15);
    static readonly TimeSpan refreshTokenLifetime = TimeSpan.FromDays(7);

    readonly JWTManager manager;
    readonly HttpRequest request;
    readonly HttpResponse response;
    readonly ClaimsTableRepository repository;
    public AuthenticationHandler(JWTManager manager, IHttpContextAccessor context, ClaimsTableRepository repository)
        => (this.manager, request, response, this.repository) = (manager, context.HttpContext!.Request, context.HttpContext!.Response, repository);

    public async Task<List<Claim>?> GetClaimsFromAuthJWT()
    {
        if (request.Headers.TryGetValue("Authorization", out var jwt))
        {
            var validation = await manager.Validate(jwt!);
            if (validation.IsValid) return validation.ClaimsIdentity.Claims.ToList();
        }
        return null;
    }

    public async Task<List<Claim>?> GetClaimsFromStorage()
    {
        if (Guid.TryParse(request.Cookies[JWTManager.AuthCookieName], out var refreshToken))
            return await repository.Get(refreshToken);
        
        return null;
    }

    public async Task<(string jwt, TimeSpan refreshHint)> StoreClaims(List<Claim> claims)
    {
        if (Guid.TryParse(request.Cookies[JWTManager.AuthCookieName], out var expiredRefreshToken))
            await repository.Drop(expiredRefreshToken);

        var refreshToken = await repository.Set(claims);
        response.Cookies.Append(JWTManager.AuthCookieName, $"{refreshToken}", new CookieOptions
        {
            Expires = DateTimeOffset.Now + refreshTokenLifetime,
            HttpOnly = true, Secure = true,
            Path = request.Host.ToString(),
            SameSite = SameSiteMode.Strict
        });

        var jwt = manager.Generate(claims, jwtLifetime);
        var refreshHint = jwtLifetime - TimeSpan.FromSeconds(30);
        return (jwt, refreshHint);
    }

    public async Task DropClaims()
    {
        response.Cookies.Append(JWTManager.AuthCookieName, string.Empty, new CookieOptions
        {
            Expires = DateTimeOffset.Now,
            HttpOnly = true, Secure = true,
            Path = request.Host.ToString(),
            SameSite = SameSiteMode.Strict
        });

        if (Guid.TryParse(request.Cookies[JWTManager.AuthCookieName], out var loggedOutToken))
            await repository.Drop(loggedOutToken);
    }
}

