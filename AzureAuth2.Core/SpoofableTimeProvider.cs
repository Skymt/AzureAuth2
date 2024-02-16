namespace AzureAuth2.Core;

public class SpoofableTimeProvider : TimeProvider
{
    TimeSpan spoofedTimeOffset = TimeSpan.Zero;
    public SpoofableTimeProvider() { }
    public SpoofableTimeProvider(TimeSpan offset) => Spoof(offset);
    public SpoofableTimeProvider(DateTimeOffset offset) => Spoof(offset);
    public SpoofableTimeProvider(DateTime offset) => Spoof(offset);

    public void Spoof(TimeSpan offset) => spoofedTimeOffset = offset;
    public void Spoof(DateTimeOffset dateAndTime) => spoofedTimeOffset = dateAndTime - base.GetUtcNow();
    public void Spoof(DateTime dateTime)
    {
        if (dateTime.Kind == DateTimeKind.Local || dateTime.Kind == DateTimeKind.Unspecified)
            Spoof(new DateTimeOffset(dateTime, TimeZoneInfo.Local.GetUtcOffset(dateTime)));
        else
            Spoof(new DateTimeOffset(dateTime, TimeSpan.Zero));
    }
    public void Reset() => spoofedTimeOffset = TimeSpan.Zero;
    
    public override DateTimeOffset GetUtcNow() => base.GetUtcNow().Add(spoofedTimeOffset);
    public override long GetTimestamp() => base.GetTimestamp() + spoofedTimeOffset.Ticks;
}