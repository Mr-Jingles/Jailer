namespace Jailer;

/// <summary>Strongly-typed configuration bound from the "Jailer" section of appsettings.json.</summary>
public sealed class JailerOptions
{
    public const string SectionName = "Jailer";

    /// <summary>Absolute path(s) of log files to monitor for new lines.</summary>
    public List<string> LogFiles { get; set; } = [];

    /// <summary>Regex applied to every new log line. A named capture group called "ip" is used
    /// for IP extraction when present; otherwise the first IPv4 literal on the matched line is used.</summary>
    public string Pattern { get; set; } = string.Empty;

    /// <summary>How many matching lines an IP must produce within <see cref="CountWindowSeconds"/> to be jailed.</summary>
    public int MatchThreshold { get; set; } = 5;

    /// <summary>Sliding window (seconds) over which per-IP matches are counted and then reset.</summary>
    public int CountWindowSeconds { get; set; } = 60;

    /// <summary>How long an IP stays blocked in iptables once the threshold is reached.</summary>
    public int JailDurationSeconds { get; set; } = 300;

    /// <summary>How often the log files are polled for new lines (milliseconds).</summary>
    public int PollIntervalMilliseconds { get; set; } = 2000;

    /// <summary>iptables-specific settings.</summary>
    public IptablesOptions Iptables { get; set; } = new();
}

/// <summary>Settings for the iptables rules Jailer creates and removes.</summary>
public sealed class IptablesOptions
{
    /// <summary>i