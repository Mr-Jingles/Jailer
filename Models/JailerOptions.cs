namespace Jailer.Models;

public class JailerOptions
{
    public List<JailRule> Jails { get; set; } = new();

    /// <summary>Default jail duration in seconds, applied when an IP is marked as jailed.</summary>
    public int JailDurationSeconds { get; set; } = 300;
}

public class JailRule
{
    public string Name { get; set; } = string.Empty;
    public string LogFile { get; set; } = string.Empty;
    public string Regex { get; set; } = string.Empty;
    public int Attempts { get; set; }
    /// <summary>Ban duration in minutes (e.g. 360).</summary>
    public int BanTime { get; set; }
}

public class IptablesSettings
{
    public string Table { get; set; } = "filter";
    public string Chain { get; set; } = "INPUT";
    public string Executable { get; set; } = "iptables";
    public string RuleTarget { get; set; } = "DROP";
}
