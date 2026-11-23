using Microsoft.Extensions.Hosting;

namespace Jailer.Services
{
    public class HostService: IHostedService
    {
        private readonly ILogger _logger;
        private ICommandRunner? _commandRunner;
        private IIptablesService? _iptablesService;
         
        public HostService() { 
            _logger = Log.ForContext<HostService>();
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.Information("Starting up...");
            var jailerOptions = new JailerOptions();
            _commandRunner = new ProcessCommandRunner();
            _iptablesService = new IptablesService(_commandRunner ,jailerOptions);


            //Here we need to create out main loop based on timers.

            //Check every min for new logs.

            //If a new ip needs jailing  then jail it.

            //if a jailed ip is now past due remove it.

            _logger.Information("Finished Start up");
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _iptablesService = null;
            _commandRunner = null;

            return Task.CompletedTask;
        }
    }
}
