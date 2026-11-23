using System.Diagnostics;

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
    private readonly ILogger _logger;

    public ProcessCommandRunner()
    {
        _logger = Log.ForContext<ProcessCommandRunner>();
    }

    public async Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default)
    {
        var args = arguments.ToArray();
        var commandLine = string.Join(' ', new[] { fileName }.Concat(args));
        _logger.Debug("Executing: {CommandLine}", commandLine);

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

            foreach (var arg in args)
            {
                process.StartInfo.ArgumentList.Add(arg);
            }

            if (!process.Start())
            {
                return new CommandResult(-1, string.Empty, $"Failed to start '{fileName}'.");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);

            _logger.Debug("{0} exited with {1}.", fileName, process.ExitCode);
            if (process.ExitCode != 0)
            {
                _logger.Warning("Command '{0}' failed (exit {1}): {2}", commandLine, process.ExitCode, stderr.Trim());
            }

            return new CommandResult(process.ExitCode, stdout, stderr);
        }
        catch (Exception ex)
        {
            _logger.Error("Failed to execute '{0}'. Is it installed and on PATH?", ex);
            return new CommandResult(-1, string.Empty, ex.Message);
        }
    }
}

/// <summary>Creates/removes iptables rules tagged with a unique comment marker so Jailer only ever touches its own entries.</summary>
public interface IIptablesService
{
    /// <summary>Inserts a blocking rule for the given IP. No-op if already jailed.</summary>
    Task<bool> JailAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>Removes the Jailer-marked blocking rule for the given IP (if present).</summary>
    Task<bool> UnjailAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>Enumerates all IPs currently blocked by a Jailer-marked rule.</summary>
    Task<IReadOnlyCollection<string>> GetJailedIpsAsync(CancellationToken cancellationToken = default);
}

public sealed class IptablesService : IIptablesService
{
    private static readonly string CommentPrefix = "jailer:";

    private readonly ICommandRunner _runner;
    private readonly JailerOptions _options;
    private readonly ILogger _logger;

    public IptablesService(ICommandRunner runner, JailerOptions options)
    {
        _runner = runner;
        _options = options;
        _logger = Log.ForContext<IptablesService>();
    }

    private string BuildComment(string ip) => $"{CommentPrefix}{ip}";

    public async Task<bool> JailAsync(string ip, CancellationToken cancellationToken = default)
    {
        var iptables = _options.Iptables;

        if (await IsJailedAsync(ip, cancellationToken).ConfigureAwait(false))
        {
            _logger.Debug("{0} is already jailed.", ip);
            return false;
        }

        // -I inserts at the top of the chain so the block takes effect immediately.
        var result = await _runner.RunAsync(iptables.Executable, new[]
        {
            "-I", iptables.Chain,
            "-s", ip,
            "-m", "comment", "--comment", BuildComment(ip),
            iptables.RuleTarget,
        }, cancellationToken).ConfigureAwait(false);

        if (!result.Success)
        {
            _logger.Error("Failed to jail {0}: {1}", ip, result.StandardError.Trim());
            return false;
        }

        _logger.Information("Jailed {0} in chain {1} (target {2}).", ip, iptables.Chain, iptables.RuleTarget);
        return true;
    }

    public async Task<bool> UnjailAsync(string ip, CancellationToken cancellationToken = default)
    {
        var iptables = _options.Iptables;

        if (!await IsJailedAsync(ip, cancellationToken).ConfigureAwait(false))
        {
            _logger.Debug("{0} is not currently jailed.", ip);
            return false;
        }

        // -D removes the first matching rule. Matching on source + comment guarantees we only
        // remove Jailer's own entry and never any unrelated rules in the chain.
        var result = await _runner.RunAsync(iptables.Executable, new[]
        {
            "-D", iptables.Chain,
            "-s", ip,
            "-m", "comment", "--comment", BuildComment(ip),
            iptables.RuleTarget,
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
        var iptables = _options.Iptables;
        var result = await _runner.RunAsync(iptables.Executable, new[] { "-S", iptables.Chain }, cancellationToken).ConfigureAwait(false);

        if (!result.Success)
        {
            _logger.Warning("Failed to list chain {0}: {1}", iptables.Chain, result.StandardError.Trim());
            return [];
        }

        var ips = new List<string>();
        foreach (var rawLine in result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (!line.Contains("--comment", StringComparison.Ordinal) || !line.Contains(CommentPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            // Extract the IP from "-s <ip>" in this rule.
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i + 1 < parts.Length; i++)
            {
                if (parts[i] == "-s" && System.Net.IPAddress.TryParse(parts[i + 1], out _))
                {
                    ips.Add(parts[i + 1]);
                    break;
                }
            }
        }

        return ips.Distinct().ToList();
    }

    private async Task<bool> IsJailedAsync(string ip, CancellationToken cancellationToken)
    {
        var jailed = await GetJailedIpsAsync(cancellationToken).ConfigureAwait(false);
        return jailed.Contains(ip, StringComparer.OrdinalIgnoreCase);
    }
}
