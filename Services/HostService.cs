using Microsoft.Extensions.Hosting;
using Jailer.Models;

namespace Jailer.Services
{
    public class HostService : IHostedService, IDisposable
    {
        private readonly ILogger _logger;
        private readonly ICommandRunner _commandRunner;
        private readonly IIptablesService _iptablesService;
        private readonly ILogMonitorService _logMonitor;
        private readonly JailerOptions _options;
        private CancellationTokenSource? _cts;
        private Task? _backgroundTask;
        private Task? _monitorTask;

        public HostService(Microsoft.Extensions.Options.IOptions<JailerOptions> options)
        {
            _logger = Log.ForContext<HostService>();
            _commandRunner = new ProcessCommandRunner();
            var jailerOptions = options.Value;
            _options = jailerOptions;
            _iptablesService = new IptablesService(_commandRunner);

            // Manually providing dependencies for LogMonitorService since we are avoiding DI in Program.cs
            var optionsWrapper = Microsoft.Extensions.Options.Options.Create(jailerOptions);
            _logMonitor = new LogMonitorService(optionsWrapper);
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.Information("Starting up...");

            _cts = new CancellationTokenSource();

            // Start log monitoring in a separate task so we don't block startup
            _monitorTask = _logMonitor.StartMonitoringAsync(_cts.Token);

            // Start the background loop in a separate task so we don't block startup
            _backgroundTask = RunMainLoopAsync(_cts.Token);
            _logger.Information("Finished Start up");
            return Task.CompletedTask;
        }

        private async Task RunMainLoopAsync(CancellationToken ct)
        {
            try
            {
                // when we start up lets clean up any left over
                await _iptablesService.CleanupAllJailsAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.Error("Failed to clean up preexisting rules: {0}", ex.Message);
            }

            // Two independent loops, one per timer. A PeriodicTimer only allows a single
            // outstanding WaitForNextTickAsync at a time, so the two timers must never be
            // awaited concurrently (that is what caused the InvalidOperationException).
            var logLoop = RunLogCheckLoopAsync(ct);
            var cleanupLoop = RunCleanupLoopAsync(ct);

            try
            {
                await Task.WhenAll(logLoop, cleanupLoop);
            }
            catch (OperationCanceledException)
            {
                _logger.Information("Main loop cancellation requested.");
            }
        }

        private async Task RunLogCheckLoopAsync(CancellationToken ct)
        {
            // Check for new violations every minute.
            using var logTimer = new PeriodicTimer(TimeSpan.FromMinutes(1));

            try
            {
                while (await logTimer.WaitForNextTickAsync(ct))
                {
                    await CheckLogsAndJailAsync();
                }
            }
            catch (OperationCanceledException)
            {
                _logger.Debug("Log check loop cancelled.");
            }
        }

        private async Task RunCleanupLoopAsync(CancellationToken ct)
        {
            // Release expired jails more frequently, e.g. every 30 seconds.
            using var cleanupTimer = new PeriodicTimer(TimeSpan.FromSeconds(30));

            try
            {
                while (await cleanupTimer.WaitForNextTickAsync(ct))
                {
                    await CleanupExpiredJailsAsync();
                }
            }
            catch (OperationCanceledException)
            {
                _logger.Debug("Cleanup loop cancelled.");
            }
        }

        private async Task CheckLogsAndJailAsync()
        {
            _logger.Debug("Checking logs for new IPs to jail...");
            var violatedIps = _logMonitor.GetViolatedIps();

            foreach (var ip in violatedIps)
            {
                if (!await _iptablesService.IsJailedAsync(ip))
                {
                    _logger.Information("Jailing IP: {0} due to log violation.", ip);
                    var jailed = await _iptablesService.JailAsync(ip);

                    // Record the expiration so the cleanup loop can release it later.
                    if (jailed)
                    {
                        _logMonitor.MarkAsJailed(ip, ruleForIp(ip));
                    }
                }
            }
        }

        /// <summary>Best-effort lookup of the jail rule that produced a violation.</summary>
        private Jailer.Models.JailRule? ruleForIp(string ip)
        {
            // The monitor does not expose which rule fired, so fall back to the first
            // configured rule's ban time when one exists.
            var jails = _options.Jails;
            return jails is { Count: > 0 } ? jails[0] : null;
        }

        private async Task CleanupExpiredJailsAsync()
        {
            _logger.Debug("Checking for expired jail entries to remove...");
            var expiredIps = await _logMonitor.GetExpiredIpsAsync();

            foreach (var ip in expiredIps)
            {
                _logger.Information("Unjailing IP: {0} - expiration reached.", ip);
                await _iptablesService.UnjailAsync(ip);
            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.Information("Stopping service...");

            if (_cts != null)
            {
                _cts.Cancel();
                try
                {
                    // Wait for the background tasks to complete gracefully
                    var pendingTasks = new[] { _backgroundTask, _monitorTask }.Where(t => t != null).Cast<Task>().ToList();
                    if (pendingTasks.Count > 0)
                    {
                        await Task.WhenAny(Task.WhenAll(pendingTasks), Task.Delay(TimeSpan.FromSeconds(5), cancellationToken));
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error("Error during graceful shutdown. {0}", ex);
                }
                finally
                {
                    _cts.Dispose();
                }
            }

        }

        public void Dispose()
        {
            _cts?.Dispose();
        }
    }
}