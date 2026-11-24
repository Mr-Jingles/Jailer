using Microsoft.Extensions.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;
using Jailer.Models;
using Jailer.Services;

namespace Jailer.Services
{
    public class HostService : IHostedService, IDisposable
    {
        private readonly ILogger _logger;
        private readonly ICommandRunner _commandRunner;
        private readonly IIptablesService _iptablesService;
        private readonly ILogMonitorService _logMonitor;
        private CancellationTokenSource? _cts;
        private Task? _backgroundTask;

        public HostService(Microsoft.Extensions.Options.IOptions<JailerOptions> options)
        {
            _logger = Log.ForContext<HostService>();
            _commandRunner = new ProcessCommandRunner();
            var jailerOptions = options.Value;
            _iptablesService = new IptablesService(_commandRunner);

            // Manually providing dependencies for LogMonitorService since we are avoiding DI in Program.cs
            var optionsWrapper = Microsoft.Extensions.Options.Options.Create(jailerOptions);
            _logMonitor = new LogMonitorService(optionsWrapper, _iptablesService);
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.Information("Starting up...");

            _cts = new CancellationTokenSource();

            // Start the background loop in a separate task so we don't block startup
            _backgroundTask = RunMainLoopAsync(_cts.Token);
            _logger.Information("Finished Start up");
            return Task.CompletedTask;
        }

        private async Task RunMainLoopAsync(CancellationToken ct)
        {
            // We use two timers (via PeriodicTimer) for the different requirements:
            // 1. Check logs every minute
            using var logTimer = new PeriodicTimer(TimeSpan.FromMinutes(1));
            // 2. Cleanup expired jails (can be more frequent, e.g., every 30 seconds)
            using var cleanupTimer = new PeriodicTimer(TimeSpan.FromSeconds(30));

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var logTask = logTimer.WaitForNextTickAsync(ct).AsTask();
                    var cleanupTask = cleanupTimer.WaitForNextTickAsync(ct).AsTask();

                    var completedTask = await Task.WhenAny(logTask, cleanupTask);

                    if (completedTask == logTask)
                    {
                        await CheckLogsAndJailAsync();
                    }
                    else
                    {
                        await CleanupExpiredJailsAsync();
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logger.Information("Main loop cancellation requested.");
            }
            catch (Exception ex)
            {
                _logger.Error("An error occurred in the main loop. {0}", ex);
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
                    _logger.Information("Jailing IP: {IP} due to log violation.", ip);
                    await _iptablesService.JailAsync(ip);
                }
            }
        }

        private async Task CleanupExpiredJailsAsync()
        {
            _logger.Debug("Checking for expired jail entries to remove...");
            var expiredIps = await _logMonitor.GetExpiredIpsAsync();

            foreach (var ip in expiredIps)
            {
                _logger.Information("Unjailing IP: {IP} - expiration reached.", ip);
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
                    // Wait for the background task to complete gracefully
                    if (_backgroundTask != null)
                    {
                        await Task.WhenAny(_backgroundTask, Task.Delay(TimeSpan.FromSeconds(5), cancellationToken));
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