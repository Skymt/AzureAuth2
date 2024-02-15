using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AzureAuth2.Core;

public static class Extensions
{
    /// <summary>
    /// Add JWT authentication scheme to the service collection. The provided configuration must contain a section named "JWT",
    /// with a key named "Secret". The keys "ValidIssuers" and "ValidAudiences" are optional. "EncryptClaims" will default to false.
    /// <para>
    /// To override an already injected TimeProvider, pass <see cref="TimeProvider.System"/> as the timeProvider parameter.
    /// </para>
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration</param>
    /// <param name="timeProvider">Optional time provider, exclusive for JWT authentication.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddJWTAuthentication(this IServiceCollection services, IConfiguration configuration, TimeProvider? timeProvider = null)
    {
        timeProvider ??= services.First(s => s.ServiceType == typeof(TimeProvider))?.ImplementationInstance as TimeProvider;

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options => options.TokenValidationParameters = JWTManager.GetValidationParameters(configuration, timeProvider));

        return services;
    }

    /// <summary>
    /// Adds a JWT manager to the service collection. The provided configuration must contain a section named "JWT",
    /// with the following keys: "Issuer", "Audience" and "Secret". The optional key "EncryptClaims" will default to false.
    /// <para>
    /// To override an already injected TimeProvider, pass <see cref="TimeProvider.System"/> as the timeProvider parameter.
    /// </para>
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="timeProvider">Optional time provider, exclusive for the jwt manager.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddJWTManager(this IServiceCollection services, TimeProvider? timeProvider = null)
    {
        services.AddSingleton(serviceHost =>
        {
            var configuration = serviceHost.GetService<IConfiguration>()!;
            return new JWTManager(configuration, timeProvider ?? serviceHost.GetService<TimeProvider>() ?? TimeProvider.System);
        });
        return services;
    }

    public static IServiceCollection AddSpoofableTimeProvider(this IServiceCollection services, out SpoofableTimeProvider timeProvider)
        => services.AddSingleton<TimeProvider>(timeProvider = new());

    ///<summary>
    /// Adds a named HTTP client to the service collection that 
    /// clones the provided JWT of an incoming request, for reuse
    /// when calling a service. No modification to the user JWT is made.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The updated service collection.</returns>
    /// <remarks>
    /// Note: The frontend can maintain its own repository of microservices and call them directly, 
    /// since the frontend is the owner of the JWT. Using this client might be a redundant step.
    /// </remarks>
    public static IServiceCollection AddUserHttpClient(this IServiceCollection services, string clientName = "UserClient")
    {
        services
            .AddHttpContextAccessor()
            .AddHttpClient(clientName, (host, client) =>
        {
            var contextService = host.GetService<IHttpContextAccessor>();
            var context = contextService!.HttpContext!;
            var authHeader = context.Request.Headers.Authorization![0]!;

            client.DefaultRequestHeaders.Authorization = new(JwtBearerDefaults.AuthenticationScheme, authHeader[7..]);
        });
        return services;
    }
}
