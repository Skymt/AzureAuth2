using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace AzureAuth2.SessionCleaner;

public class ClaimsTableCleanerFunction(ILoggerFactory loggerFactory, ClaimsTableRepository repository)
{
    private readonly ILogger _logger = loggerFactory.CreateLogger<ClaimsTableCleanerFunction>();

    [Function("ClaimsTableCleaner")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "Required for attribute binding.")]
    public async Task Run([TimerTrigger("30 0 * * *", RunOnStartup = true)] TimerInfo timer)
    {
        _logger.LogInformation("Claims table cleanup of expired sessions starting: {DateTime.Now:u}", DateTime.Now);
        var expiredClaimsCount = await repository.DropExpired();
        _logger.LogInformation("Claims table cleanup of {expiredClaimsCount} expired sessions finished: {DateTime.Now:u}", expiredClaimsCount, DateTime.Now);
    }
}
