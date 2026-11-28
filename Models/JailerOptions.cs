using System.Text.Json.Serialization;

namespace Jailer.Models;

// Trim-safe deserialization: the JSON is read with a source-generated serializer (JailerJsonContext)
// instead of reflection-based configuration binding, so trimmed publishes keep working.
public class JailerOptions
{
    public List<JailRule> Jails { get; set; } = new();
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
    /// <summary>Executable for IPv6 rules (e.g., ip6tables).</summary>
    public string Ip6Executable { get; set; } = "ip6tables";
    public string RuleTarget { get; set; } = "DROP";
}

/// <summary>
/// Source-generated JSON serializer context. Using this (instead of reflection-based
/// configuration binding) is what makes deserialization survive .NET trimming.
/// </summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(JailerOptions))]
internal partial class JailerJsonContext : JsonSerializerContext
{
}
