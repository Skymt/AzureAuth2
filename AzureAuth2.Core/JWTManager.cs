using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AzureAuth2.Core;
public class JWTManager
{
    public static readonly string AuthCookieName = "AuthID";

    readonly string issuer; readonly string audience;
    readonly TokenValidationParameters validationParameters;
    readonly SigningCredentials signingCredentials;
    readonly JwtSecurityTokenHandler tokenHandler;
    readonly EncryptingCredentials? encryptingCredentials;
    readonly TimeProvider timeProvider;
    public JWTManager(IConfiguration configuration, TimeProvider timeProvider)
    {
        issuer = configuration["JWT:Issuer"]!; audience = configuration["JWT:Audience"]!;
        validationParameters = GetValidationParameters(configuration, timeProvider);
        signingCredentials = new SigningCredentials(
            validationParameters.IssuerSigningKey,
            SecurityAlgorithms.HmacSha256);
        encryptingCredentials = validationParameters.TokenDecryptionKey switch
        {
            SymmetricSecurityKey key => new(key,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128CbcHmacSha256),
            _ => null
        };
        tokenHandler = new();
        this.timeProvider = timeProvider;
    }
    
    /// <summary>
    /// Validates a JWT.
    /// </summary>
    /// <param name="token">The token to validate</param>
    /// <param name="claims">The claims contained within the JWT, or null if the token is invalid.</param>
    /// <returns>True if the token was valid</returns>
    public bool Validate(string token, out IEnumerable<Claim>? claims)
    {
        try
        {
            var principal = tokenHandler.ValidateToken(token.Replace(JwtBearerDefaults.AuthenticationScheme, string.Empty).Trim(), validationParameters, out _);
            claims = principal.Claims;
            return true;
        }
        catch
        {
            claims = null;
            return false;
        }
    }
    
    /// <summary>
    /// Validates a JWT.
    /// </summary>
    /// <param name="token">The token to validate</param>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> entity or null if the token is invalid.</param>
    /// <param name="validatedToken">The validated <see cref="SecurityToken"/>.</param>
    /// <returns>True if the token was valid</returns>
    public bool Validate(string token, out ClaimsPrincipal? principal, out SecurityToken? validatedToken)
    {
        try
        {
            principal = tokenHandler.ValidateToken(token.Replace(JwtBearerDefaults.AuthenticationScheme, string.Empty).Trim(), validationParameters, out validatedToken);
            return true;
        }
        catch
        {
            principal = null; validatedToken = null;
            return false;
        }
    }
    
    /// <summary>
    /// Gets the error message from validation.
    /// </summary>
    /// <param name="token">The token to validate</param>
    /// <param name="textIfValid">The text to return should the JWT be valid</param>
    /// <returns>The error message from validation.</returns>
    public string Validate(string token, string textIfValid = "")
    {
        try
        {
            tokenHandler.ValidateToken(token.Replace(JwtBearerDefaults.AuthenticationScheme, string.Empty).Trim(), validationParameters, out _);
            return textIfValid;
        }
        catch (Exception ex) { return ex.Message; }
    }

    /// <summary>
    /// Validates a token asynchronously.
    /// </summary>
    /// <param name="token">The token to validate</param>
    /// <returns>A task that resolves to a <see cref="TokenValidationResult"/> when completed.</returns>
    public Task<TokenValidationResult> ValidateAsync(string token)
        => tokenHandler.ValidateTokenAsync(token.Replace("Bearer ", string.Empty), validationParameters);

    /// <summary>
    /// Generates a new JWT token with the provided claims and duration.
    /// </summary>
    /// <param name="claims">The claimed rights of this JWT</param>
    /// <param name="duration">The duration of the JWT</param>
    /// <param name="audience">Override the default audience.</param>
    /// <exception cref="ArgumentOutOfRangeException">If the secret key is too short</exception>
    /// <returns>A JWT string.</returns>
    public string Generate(IEnumerable<Claim> claims, TimeSpan duration, string? audience = null)
    {
        var currentAudience = audience ?? this.audience;
        var distinctClaims = claims
            .GroupBy(c => c.Type + c.Value)
            .Select(g => g.First())
            .Where(claimIsNotCurrentAudience);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(distinctClaims),
            NotBefore = now, IssuedAt = now,
            Expires = now.Add(duration),
            Issuer = issuer,
            Audience = currentAudience,
            SigningCredentials = signingCredentials,
        };

        if (encryptingCredentials != null)
            tokenDescription.EncryptingCredentials = encryptingCredentials;

        return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescription));
        bool claimIsNotCurrentAudience(Claim c) => !(c.Type == "aud" && c.Value == currentAudience);
    }

    /// <summary>
    /// Reads the provided configuration to create a new instance of <see cref="TokenValidationParameters"/>.
    /// </summary>
    /// <param name="configuration">The configuration containing values for JWT generation</param>
    /// <exception cref="NullReferenceException">If the required JWT:Secret value is missing from configuration</exception>
    /// <returns>A new instance of <see cref="TokenValidationParameters"/></returns>
    public static TokenValidationParameters GetValidationParameters(IConfiguration configuration, TimeProvider? timeProvider = null)
    {
        byte[] secretKey = Encoding.ASCII.GetBytes(configuration["JWT:Secret"]!);
        var issuers = configuration["JWT:ValidIssuers"]?.Split(',');
        var audiences = configuration["JWT:ValidAudiences"]?.Split(',');
        var encryptClaims = configuration.GetValue("JWT:EncryptClaims", false);

        SymmetricSecurityKey signerKey = new(secretKey);
        SymmetricSecurityKey? cryptoKey = encryptClaims ? new(secretKey[..16]) : null;
        return new()
        {
            IssuerSigningKey = signerKey,
            ValidateLifetime = true,
            ValidateIssuer = issuers != null,
            ValidIssuers = issuers,
            ValidateAudience = audiences != null,
            ValidAudiences = audiences,
            TokenDecryptionKey = cryptoKey,
            LifetimeValidator = (notBefore, expires, _, _) =>
            {
                var now = timeProvider?.GetUtcNow().UtcDateTime ?? TimeProvider.System.GetUtcNow().UtcDateTime;
                return notBefore.HasValue && notBefore < now && expires.HasValue && expires > now;
            }
        };
    }

    /// <summary>
    /// Generates a new shared secret to be put in configuration.
    /// </summary>
    /// <returns>72 random characters in a string.</returns>
    /// <remarks>This method does not update any configuration!</remarks>
    public static string GenerateNewSharedSecret()
    {
        var buffer = new Span<byte>(new byte[54]); // (54 bytes * 8 bits) / (6 bits / sextet) = (72 sextets)
        Random.Shared.NextBytes(buffer);
        return Convert.ToBase64String(buffer);
    }
}