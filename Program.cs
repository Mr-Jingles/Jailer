using Jailer.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = new HostBuilder()
    .ConfigureAppConfiguration((hostingContext, config) =>
    {
    })
    .ConfigureServices((hostContext, services) =>
    {
        services.AddOptions();
        services.AddSingleton<IHostedService, HostService>();
    });

await builder.RunConsoleAsync();
