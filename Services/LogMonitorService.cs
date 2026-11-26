using System.Text.RegularExpressions;
using Jailer.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Jailer.Services
{
    /// <summary>A single entry in the jail state: which jail it belongs to, the IP, and when the ban expires.</summary>
    public sealed record JailedIp(string JailName, string Ip, DateTime ExpiresUtc);

    public class LogMonitorService : BackgroundService, ILogMonitorService
    {
        // The jail rule's regex identifies *which lines* are violations, but it does not
        // necessarily capture the offending IP (e.g. "Test.*" matches the whole line).
        // Extract an IPv4 address from a matched line instead of using the raw match value.
        private static readonly Regex IpAddressRegex = new(
            @"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            RegexOptions.Compiled);

        /// <summary>
        /// Extracts the offending IP from a matched log line. Prefers an address wrapped in
        /// parentheses — fail2ban's &lt;HOST&gt; convention for lines such as
        /// "refused connect from 10.9.8.7 (192.168.1.5)" where the parenthesised value is the
        /// client address — and falls back to the first bare IPv4 in the line.
        /// </summary>
        public static string? ExtractIp(string line)
        {
            var parenthesized = System.Text.RegularExpressions.Regex.Match(
                line, @"\((\d{1,3}(?:\.\d{1,3}){3})\)");
            if (parenthesized.Success && System.Net.IPAddress.TryParse(parenthesized.Groups[1].Value, out _))
            {
                return parenthesized.Groups[1].Value;
            }

            var first = IpAddressRegex.Match(line);
            return first.Success ? first.Value : null;
        }

        /// <summary>Attempt counts older than this are dropped, so a slow drip of one bad attempt per day never adds up to a ban. (Settable for testing.)</summary>
        public static TimeSpan AttemptWindow { get; set; } = TimeSpan.FromHours(24);

        private readonly JailerOptions _options;
        private readonly ILogger _logger = Log.ForContext<LogMonitorService>();

        // Jail state, grouped by jail name so the summary can show every configured jail.
        private readonly Dictionary<string, Dictionary<string, DateTime>> _jailedIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _violatedIps = new();
        private readonly object _lock = new();

        /// <summary>Invoked immediately when an IP reaches its attempt threshold. HostService uses this to jail the IP at once instead of waiting for the periodic check.</summary>
        public Action<string, JailRule>? ViolationDetected { get; set; }

        public LogMonitorService(IOptions<JailerOptions> options)
        {
            _options = options.Value;
        }

        public IEnumerable<string> GetViolatedIps()
        {
            lock (_lock)
            {
                var ips = _violatedIps.ToList();
                _violatedIps.Clear();
                return ips;
            }
        }

        public Task<IEnumerable<JailedIp>> GetExpiredIpsAsync()
        {
            var expired = new List<JailedIp>();
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                foreach (var kvp in _jailedIps)
                {
                    foreach (var entry in kvp.Value.ToList())
                    {
                        if (now >= entry.Value)
                        {
                            expired.Add(new JailedIp(kvp.Key, entry.Key, entry.Value));
                        }
                    }
                }

                // Remove after enumeration so the same IP is not reported (and unjailed) again next cycle.
                foreach (var jail in _jailedIps.Values)
                {
                    var toRemove = jail.Where(kvp => now >= kvp.Value).Select(kvp => kvp.Key).ToList();
                    foreach (var ip in toRemove)
                    {
                        jail.Remove(ip);
                    }
                }
            }

            return Task.FromResult<IEnumerable<JailedIp>>(expired);
        }

        /// <summary>Snapshot of the current jail state, grouped by jail name.</summary>
        public Dictionary<string, List<(string Ip, DateTime ExpiresUtc)>> GetJailState()
        {
            lock (_lock)
            {
                var snapshot = new Dictionary<string, List<(string Ip, DateTime ExpiresUtc)>>(StringComparer.OrdinalIgnoreCase);
                foreach (var kvp in _jailedIps)
                {
                    snapshot[kvp.Key] = kvp.Value.Select(j => (Ip: j.Key, ExpiresUtc: j.Value)).ToList();
                }

                return snapshot;
            }
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken) => StartMonitoringCore(stoppingToken);

        public Task StartMonitoringAsync(CancellationToken ct) => StartMonitoringCore(ct);

        private async Task StartMonitoringCore(CancellationToken ct)
        {
            if (_options.Jails == null || _options.Jails.Count == 0)
            {
                _logger.Information("No jail rules configured.");
                return;
            }

            var monitorTasks = new List<Task>();
            foreach (var jail in _options.Jails)
            {
                // Validate the rule up front so a bad regex is reported once at startup
                // instead of crashing the monitoring loop on the first log line.
                if (!TryCompileRule(jail, out var compiled))
                {
                    continue;
                }

                monitorTasks.Add(MonitorLogFileAsync(jail, compiled, ct));
            }

            await Task.WhenAll(monitorTasks);
        }

        private bool TryCompileRule(JailRule rule, out Regex regex)
        {
            try
            {
                // Fail2BanFilter.Translate handles fail2ban constructs (%(...)s variables, <HOST>);
                // plain .NET patterns pass through unchanged.
                regex = Fail2BanFilter.Compile(rule.Regex);
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error("Skipping jail '{0}': invalid regex ({1})", rule.Name, ex.Message);
                regex = null!;
                return false;
            }
        }

        private async Task MonitorLogFileAsync(JailRule rule, Regex compiledRegex, CancellationToken ct)
        {
            _logger.Information("Starting monitoring for jail: {0} on file: {1}", rule.Name, rule.LogFile);

            // (attempt count, time of last attempt) per IP. The window check in HandleIpMatchAsync
            // resets stale counts so attempts older than AttemptWindow do not accumulate.
            var ipAttempts = new Dictionary<string, (int Count, DateTime LastAttemptUtc)>();

            try
            {
                while (!File.Exists(rule.LogFile) && !ct.IsCancellationRequested)
                {
                    _logger.Debug("Waiting for log file to appear: {0}", rule.LogFile);
                    await Task.Delay(5000, ct).ContinueWith(_ => { });
                }

                using var fs = new FileStream(rule.LogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(fs);
                fs.Seek(0, SeekOrigin.End);

                while (!ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync();
                    if (line == null)
                    {
                        await Task.Delay(500, ct).ContinueWith(_ => { });
                        continue;
                    }

                    if (compiledRegex.IsMatch(line))
                    {
                        var ip = ExtractIp(line);
                        if (!string.IsNullOrEmpty(ip))
                        {
                            await HandleIpMatchAsync(rule, ip, ipAttempts);
                        }
                        else
                        {
                            _logger.Warning("Line matched jail {0} but no valid IP address was found: {1}", rule.Name, line);
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.Error("Error monitoring {0}: {1}", rule.Name, ex.Message);
            }
        }

        private async Task HandleIpMatchAsync(JailRule rule, string ip, Dictionary<string, (int Count, DateTime LastAttemptUtc)> ipAttempts)
        {
            var now = DateTime.UtcNow;

            if (!ipAttempts.TryGetValue(ip, out var attempt))
            {
                attempt = (0, now);
            }

            // Drop counts older than the window: one bad attempt a day must never add up to a ban.
            if (now - attempt.LastAttemptUtc > AttemptWindow)
            {
                attempt = (0, now);
            }

            var count = attempt.Count + 1;
            ipAttempts[ip] = (count, now);
            _logger.Debug("IP {0} matched pattern in jail {1}. Count: {2}/{3}", ip, rule.Name, count, rule.Attempts);

            if (count >= rule.Attempts)
            {
                lock (_lock)
                {
                    _violatedIps.Add(ip);
                }
                _logger.Information("Violation detected for IP: {0} in jail {1}", ip, rule.Name);
                ipAttempts[ip] = (0, now);

                // Jail immediately instead of waiting up to a minute for the periodic check.
                ViolationDetected?.Invoke(ip, rule);
            }

            await Task.CompletedTask;
        }

        public Task AddJailedIpAsync(string ip, TimeSpan duration)
        {
            MarkAsJailed(ip, null, duration);
            return Task.CompletedTask;
        }

        public void MarkAsJailed(string ip) => MarkAsJailed(ip, (JailRule?)null);

        public void MarkAsJailed(string ip, JailRule? rule)
        {
            var duration = rule?.BanTime > 0 ? TimeSpan.FromMinutes(rule.BanTime) : JailDuration;
            MarkAsJailed(ip, rule, duration);
        }

        private void MarkAsJailed(string ip, JailRule? rule, TimeSpan duration)
        {
            var jailName = string.IsNullOrEmpty(rule?.Name) ? "unknown" : rule.Name;
            var expires = DateTime.UtcNow.Add(duration);
            lock (_lock)
            {
                if (!_jailedIps.TryGetValue(jailName, out var jail))
                {
                    jail = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
                    _jailedIps[jailName] = jail;
                }

                jail[ip] = expires;
            }
            _logger.Information("IP {0} has been marked as jailed in '{1}' until {2}", ip, jailName, expires);
        }

        public async Task RemoveJailedIpAsync(string ip)
        {
            lock (_lock)
            {
                foreach (var jail in _jailedIps.Values)
                {
                    jail.Remove(ip);
                }
            }
            _logger.Information("IP {0} has been removed from the jailed list", ip);
            await Task.CompletedTask;
        }

        public TimeSpan JailDuration => TimeSpan.FromMinutes(1);
    }
}
