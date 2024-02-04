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
            var validation = await manager.Validate(jwt[0]![7..]);
            if (validation.IsValid) return validation.ClaimsIdentity.Claims.ToList();
        }
        return null;
    }

    public async Task<List<Claim>?> GetClaimsFromStorage()
    {
        if (Guid.TryParse(request.Cookies[JWTManager.AuthCookieName], out var refreshToken))
        {
            var claims = await repository.Get(refreshToken);
            if(claims != null) return claims;
        }
        return null;
    }

    public async Task<(string jwt, TimeSpan refreshHint)> StoreClaims(List<Claim> claims)
    {
        if (Guid.TryParse(request.Cookies[JWTManager.AuthCookieName], out var expiredRefreshToken))
            await repository.Drop(expiredRefreshToken);

        var entity = await repository.Store(claims);
        response.Cookies.Append(JWTManager.AuthCookieName, $"{entity.RefreshToken}", new CookieOptions
        {
            Expires = DateTimeOffset.Now + refreshTokenLifetime,
            HttpOnly = true, Secure = true,
            Path = request.Host.ToString(),
            SameSite = SameSiteMode.Strict
        });
        return (manager.Generate(claims, jwtLifetime), jwtLifetime - TimeSpan.FromSeconds(30));
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

