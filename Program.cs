using Microsoft.Extensions.DependencyInjection;
using Jailer.Services;
using Microsoft.Extensions.Hosting;

var logger = Jailer.Log.ForContext<Program>();

try
{
    logger.Information("Starting Jailer application...");

    var builder = new HostBuilder()
        .ConfigureAppConfiguration((hostingContext, config) =>
        {
        })
        .ConfigureServices((hostContext, services) =>
        {
            services.AddSingleton<IHostedService, HostService>();
        });

    await builder.RunConsoleAsync();
}
catch (Exception ex)
{
    logger.Error("Application terminated unexpectedly {0}", ex);
}
