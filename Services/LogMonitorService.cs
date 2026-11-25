using System.Text.RegularExpressions;
using Jailer.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Jailer.Services
{
    public class LogMonitorService : BackgroundService, ILogMonitorService
    {
        private readonly JailerOptions _options;
        private readonly ILogger _logger = Log.ForContext<LogMonitorService>();

        // Track IPs that have been jailed and their expiration time
        private readonly Dictionary<string, DateTime> _jailedIps = new();
        private readonly HashSet<string> _violatedIps = new();
        private readonly object _lock = new();

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

        public async Task<IEnumerable<string>> GetExpiredIpsAsync()
        {
            var expiredIps = new List<string>();
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                foreach (var kvp in _jailedIps)
                {
                    if (now >= kvp.Value)
                    {
                        expiredIps.Add(kvp.Key);
                    }
                }
            }
            return await Task.FromResult(expiredIps);
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

            var monitorTasks = _options.Jails.Select(jail => MonitorLogFileAsync(jail, ct));
            await Task.WhenAll(monitorTasks);
        }

        private async Task MonitorLogFileAsync(JailRule rule, CancellationToken ct)
        {
            _logger.Information("Starting monitoring for jail: {0} on file: {1}", rule.Name, rule.LogFile);
            var ipAttempts = new Dictionary<string, int>();

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

                    Match ipMatch = Regex.Match(line, rule.Regex);
                    if (ipMatch.Success)
                    {
                        string? ip = ipMatch.Value;
                        if (!string.IsNullOrEmpty(ip))
                        {
                            await HandleIpMatchAsync(rule, ip, ipAttempts, ct);
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

        private async Task HandleIpMatchAsync(JailRule rule, string ip, Dictionary<string, int> ipAttempts, CancellationToken ct)
        {
            if (!ipAttempts.TryGetValue(ip, out int count))
            {
                count = 0;
            }

            count++;
            ipAttempts[ip] = count;
            _logger.Debug("IP {0} matched pattern in jail {1}. Count: {2}/{3}", ip, rule.Name, count, rule.Attempts);

            if (count >= rule.Attempts)
            {
                lock (_lock)
                {
                    if (!_violatedIps.Contains(ip))
                    {
                        _violatedIps.Add(ip);
                    }
                }
                _logger.Information("Violation detected for IP: {0} in jail {1}", ip, rule.Name);
                ipAttempts[ip] = 0;
            }

            await Task.CompletedTask;
        }

        public async Task AddJailedIpAsync(string ip, TimeSpan duration)
        {
            lock (_lock)
            {
                _jailedIps[ip] = DateTime.UtcNow.Add(duration);
            }
            _logger.Information("IP {0} has been added to the jailed list until {1}", ip, _jailedIps[ip]);
            await Task.CompletedTask;
        }

        public void MarkAsJailed(string ip) => MarkAsJailed(ip, null);

        public void MarkAsJailed(string ip, JailRule? rule)
        {
            var duration = rule?.BanTime > 0 ? TimeSpan.FromMinutes(rule.BanTime) : JailDuration;
            lock (_lock)
            {
                _jailedIps[ip] = DateTime.UtcNow.Add(duration);
            }
            _logger.Information("IP {0} has been marked as jailed until {1}", ip, _jailedIps[ip]);
        }

        public async Task RemoveJailedIpAsync(string ip)
        {
            lock (_lock)
            {
                _jailedIps.Remove(ip);
            }
            _logger.Information("IP {0} has been removed from the jailed list", ip);
            await Task.CompletedTask;
        }

        public TimeSpan JailDuration => TimeSpan.FromMinutes(1);
    }
}