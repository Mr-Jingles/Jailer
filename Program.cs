using System;
using System.Threading.Tasks;
using Jailer.Services;
using Microsoft.Extensions.Hosting;

var logger = Jailer.Log.ForContext<Program>();

try
{
    logger.Information("Starting Jailer application...");

    // Manual instantiation of HostService as requested to avoid standard DI in Program.cs
    var hostService = new HostService();

    using var host = new HostBuilder()
        .ConfigureLogging(logging => logging.ClearProviders().AddConsole()) // Or any other logger configuration if needed
        .AddHostedService(hostService)
        .Build();

    await host.RunAsync();
}
catch (Exception ex)
{
    logger.Error("Application terminated unexpectedly {0}", ex);
}
