using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Jailer.Services;
using Microsoft.Extensions.Hosting;
using Jailer;
using Jailer.Models;

var logger = new Logger(null);

try
{
    logger.Information("Starting Jailer application...");

    var builder = new HostBuilder()
        .ConfigureAppConfiguration((hostingContext, config) =>
        {
            config.AddJsonFile("jails.json", optional: true, reloadOnChange: false);
        })
        .ConfigureServices((hostContext, services) =>
        {
            services.Configure<JailerOptions>(hostContext.Configuration);
            services.AddSingleton<IHostedService, HostService>();
        });

    await builder.RunConsoleAsync();
}
catch (Exception ex)
{
    logger.Error("Application terminated unexpectedly {0}", ex);
}
