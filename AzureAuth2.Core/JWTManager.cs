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
    public JWTManager(IConfiguration configuration)
    {
        issuer = configuration["JWT:Issuer"]!; audience = configuration["JWT:Audience"]!;
        validationParameters = GetValidationParameters(configuration);
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
    }

    public Task<TokenValidationResult> Validate(string token)
        => tokenHandler.ValidateTokenAsync(token.Replace("Bearer ", string.Empty), validationParameters);
    public string Generate(IEnumerable<Claim> claims, TimeSpan duration, string? audience = null)
    {
        var currentAudience = audience ?? this.audience;
        var distinctClaims = claims
            .GroupBy(c => c.Type + c.Value)
            .Select(g => g.First())
            .Where(claimIsNotCurrentAudience);

        var tokenDescription = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(distinctClaims),
            Expires = DateTime.UtcNow.Add(duration),
            Issuer = issuer,
            Audience = currentAudience,
            SigningCredentials = signingCredentials,
        };

        if (encryptingCredentials != null)
            tokenDescription.EncryptingCredentials = encryptingCredentials;

        var jwt = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescription));

        return jwt;
        bool claimIsNotCurrentAudience(Claim c) => !(c.Type == "aud" && c.Value == currentAudience);
    }

    public static TokenValidationParameters GetValidationParameters(IConfiguration configuration)
    {
        SymmetricSecurityKey key = new(Encoding.ASCII.GetBytes(configuration["JWT:Secret"]!));
        var issuers = configuration["JWT:ValidIssuers"]?.Split(',');
        var audiences = configuration["JWT:ValidAudiences"]?.Split(',').ToHashSet();
        var encrypted = configuration.GetValue("JWT:EncryptClaims", false);

        var parameters = new TokenValidationParameters
        {
            IssuerSigningKey = key, ValidateLifetime = true, 
            ValidateIssuer = issuers != null, ValidIssuers = issuers,
            ValidateAudience = audiences != null, ValidAudiences = audiences,
        };
        if (encrypted)
            parameters.TokenDecryptionKey = 
                new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JWT:Secret"]![..16]));

        return parameters;
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