using System.Diagnostics;
using Microsoft.Extensions.Options;

namespace Jailer.Services;

/// <summary>Result of an external process invocation.</summary>
public sealed record CommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Success => ExitCode == 0;
}

/// <summary>Executes iptables (and other Linux commands) via <see cref="Process"/> and captures output.</summary>
public interface ICommandRunner
{
    Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default);
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    private readonly ILogger _logger = Log.ForContext<ProcessCommandRunner>();

    public async Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };

            foreach (var arg in arguments)
            {
                process.StartInfo.ArgumentList.Add(arg);
            }

            if (!process.Start())
            {
                return new CommandResult(-1, string.Empty, $"Failed to start '{fileName}'.");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

                if (process.ExitCode != 0)
                {
                    _logger.Warning("Command '{0} {1}' failed (exit {2}): {3}", fileName, string.Join(' ', arguments), process.ExitCode, stderr.Trim());
                }

            return new CommandResult(process.ExitCode, stdout, stderr);
        }
        catch (Exception ex)
        {
            _logger.Error("Failed to execute '{0}' with ex {1}.", fileName, ex);
            throw;
        }
    }
}

/// <summary>Provides high-level operations for managing iptables rules.</summary>
public interface IIptablesService
{
    /// <summary>Inserts a blocking rule for the given IP. No-op if already jailed.</summary>
    Task<bool> JailAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>Removes the Jailer-marked blocking rule for the given IP (if present).</summary>
    Task<bool> UnjailAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>Returns true if the given IP is currently blocked by a Jailer-marked rule.</summary>
    Task<bool> IsJailedAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>Enumerates all IPs currently blocked by a Jailer-marked rule.</summary>
    Task<IReadOnlyCollection<string>> GetJailedIpsAsync(CancellationToken cancellationToken = default);

    /// <summary>Removes all rules tagged with the Jailer comment prefix.</summary>
    Task CleanupAllJailsAsync(CancellationToken cancellationToken = default);
}

/// <summary>Settings for the iptables rules Jailer creates and removes.</summary>
public sealed class IptablesOptions
{
    public string Executable { get; set; } = "iptables";

    /// <summary>Executable for IPv6 rules (e.g., ip6tables).</summary>
    public string Ip6Executable { get; set; } = "ip6tables";

    public string Chain { get; set; } = "INPUT";

    public string RuleTarget { get; set; } = "DROP";
}

public sealed class IptablesService : IIptablesService
{
    private static readonly string CommentPrefix = "jailer:";
    private readonly ICommandRunner _runner;
    private readonly IptablesOptions _options;

    private readonly ILogger _logger = Log.ForContext<IptablesService>();

    public IptablesService(ICommandRunner runner)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _options = new IptablesOptions();
    }

    public IptablesService(ICommandRunner runner, IOptions<IptablesOptions> options)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _options = options.Value;
    }

    private string BuildComment(string ip) => $"{CommentPrefix}{ip}";

    /// <summary>
    /// Normalizes an IP address to its canonical string form (compressed IPv6, e.g.
    /// 2001:db8:3c4d:0015:: -> 2001:db8:3c4d:15::). iptables normalizes the -s argument
    /// but stores --comment verbatim, so jail/unjail must always use the same form or
    /// the comment rebuilt at unjail time will not match the one stored at jail time.
    /// Unparseable input is returned unchanged.
    /// </summary>
    private static string NormalizeIp(string ip)
    {
        if (System.Net.IPAddress.TryParse(ip, out var address))
        {
            return address.ToString();
        }

        return ip;
    }

    private string GetExecutable(string ip)
    {
        if (System.Net.IPAddress.TryParse(ip, out var address))
        {
            return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 
                ? _options.Ip6Executable 
                : _options.Executable;
        }
        return _options.Executable;
    }

    public async Task<bool> JailAsync(string ip, CancellationToken cancellationToken = default)
    {
        ip = NormalizeIp(ip);

        if (await IsJailedAsync(ip, cancellationToken).ConfigureAwait(false))
        {
            _logger.Debug("{0} is already jailed.", ip);
            return false;
        }

        var executable = GetExecutable(ip);

        // -I inserts at the top of the chain so the block takes effect immediately.
        var result = await _runner.RunAsync(executable, new[]
        {
            "-I", _options.Chain,
            "-s", ip,
            "-m", "comment", "--comment", BuildComment(ip),
            "-j", _options.RuleTarget,
        }, cancellationToken).ConfigureAwait(false);

        if (!result.Success)
        {
            _logger.Error("Failed to jail {0}: {1}", ip, result.StandardError.Trim());
            return false;
        }

        _logger.Information("Jailed {0} in chain {1} (target {2}).", ip, _options.Chain, _options.RuleTarget);
        return true;
    }

    public async Task<bool> UnjailAsync(string ip, CancellationToken cancellationToken = default)
    {
        ip = NormalizeIp(ip);

        if (!await IsJailedAsync(ip, cancellationToken).ConfigureAwait(false))
        {
            _logger.Debug("{0} is not currently jailed.", ip);
            return false;
        }

        var executable = GetExecutable(ip);

        // -D removes the first matching rule. Matching on source + comment guarantees we only
        // remove Jailer's own entry and never any unrelated rules in the chain.
        var result = await _runner.RunAsync(executable, new[]
        {
            "-D", _options.Chain,
            "-s", ip,
            "-m", "comment", "--comment", BuildComment(ip),
            "-j", _options.RuleTarget,
        }, cancellationToken).ConfigureAwait(false);

        if (!result.Success)
        {
            _logger.Error("Failed to unjail {0}: {1}", ip, result.StandardError.Trim());
            return false;
        }

        _logger.Information("Unjailed {0}.", ip);
        return true;
    }

    public async Task<IReadOnlyCollection<string>> GetJailedIpsAsync(CancellationToken cancellationToken = default)
    {
        var ips = new List<string>();
        
        // We need to check both iptables and ip6tables for rules.
        await AddJailedIpsFromBinary(_options.Executable, _options.Chain, ips, cancellationToken);
        await AddJailedIpsFromBinary(_options.Ip6Executable, _options.Chain, ips, cancellationToken);

        return ips.Distinct().ToList();
    }

    private async Task AddJailedIpsFromBinary(string executable, string chain, List<string> ipList, CancellationToken ct)
    {
        var result = await _runner.RunAsync(executable, new[] { "-S", chain }, ct).ConfigureAwait(false);

        if (!result.Success)
        {
            _logger.Warning("Failed to list chain {0} using {1}: {2}", chain, executable, result.StandardError.Trim());
            return;
        }

        foreach (var rawLine in result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (!line.Contains("--comment", StringComparison.Ordinal) || !line.Contains(CommentPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i + 1 < parts.Length; i++)
            {
                if (parts[i] != "-s")
                {
                    continue;
                }

                var candidate = parts[i + 1];
                var slash = candidate.IndexOf('/');
                if (slash > 0)
                {
                    candidate = candidate[..slash];
                }

                if (System.Net.IPAddress.TryParse(candidate, out var parsed))
                {
                    // Normalize so callers comparing against raw input IPs (e.g. the
                    // zero-padded form captured from a log line) still match.
                    ipList.Add(parsed.ToString());
                    break;
                }
            }
        }
    }

    public async Task CleanupAllJailsAsync(CancellationToken cancellationToken = default)
    {
        _logger.Information("Cleaning up all Jailer-marked rules...");
        var jailedIps = await GetJailedIpsAsync(cancellationToken).ConfigureAwait(false);
        
        foreach (var ip in jailedIps)
        {
            await UnjailAsync(ip, cancellationToken).ConfigureAwait(false);
        }

        _logger.Information("Cleanup complete. Removed {0} rules.", jailedIps.Count);
    }

    public async Task<bool> IsJailedAsync(string ip, CancellationToken cancellationToken = default)
    {
        var jailed = await GetJailedIpsAsync(cancellationToken).ConfigureAwait(false);
        return jailed.Contains(NormalizeIp(ip), StringComparer.OrdinalIgnoreCase);
    }
}