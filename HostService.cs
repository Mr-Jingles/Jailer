using Microsoft.Extensions.Hosting;

namespace Jailer.Services
{
    public class HostService: IHostedService
    {
        private readonly ILogger _logger;
         
        public HostService() { 
            _logger = Log.ForContext<HostService>();

            _logger.Error("Start up {0}", "yes");
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
