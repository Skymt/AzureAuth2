using Microsoft.IdentityModel.Tokens;

namespace AzureAuth2.Core;

public class SpoofableTimeProvider : TimeProvider
{
    TimeSpan spoofedTimeOffset = TimeSpan.Zero;
    public SpoofableTimeProvider() { }
    public SpoofableTimeProvider(TimeSpan offset) => Spoof(offset);
    public SpoofableTimeProvider(DateTimeOffset offset) => Spoof(offset);

    public void Spoof(TimeSpan offset) => spoofedTimeOffset = offset;
    public void Spoof(DateTimeOffset utcDateAndTime) => spoofedTimeOffset = utcDateAndTime - base.GetUtcNow();
    public void Reset() => spoofedTimeOffset = TimeSpan.Zero;
    
    public LifetimeValidator LifetimeValidator => (notBefore, expires, _, _) =>
    {
        var now = GetUtcNow();
        return (!notBefore.HasValue || notBefore < now) && (!expires.HasValue || expires > now);
    };

    public override DateTimeOffset GetUtcNow() => base.GetUtcNow().Add(spoofedTimeOffset);
    public override long GetTimestamp() => base.GetTimestamp() + spoofedTimeOffset.Ticks;
}