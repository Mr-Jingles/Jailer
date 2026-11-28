using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Jailer.Services;
using Microsoft.Extensions.Hosting;
using Jailer;
using Jailer.Models;

var logger = new Logger(null);

try
{
    logger.Information("Starting Jailer application...");

    // Load jail rules with a source-generated (trim-safe) serializer instead of
    // reflection-based configuration binding, which the trimmer silently breaks.
    var jailsPath = Path.Combine(AppContext.BaseDirectory, "jails.json");
    logger.Information("Loading jail rules from {0}", jailsPath);

    JailerOptions options;
    try
    {
        options = JsonSerializer.Deserialize(File.ReadAllText(jailsPath), JailerJsonContext.Default.JailerOptions)
                  ?? throw new InvalidDataException("jails.json deserialized to null.");
    }
    catch (FileNotFoundException) when (!File.Exists(jailsPath))
    {
        logger.Error("Configuration file not found: {0}", jailsPath);
        return 1;
    }

    if (options.Jails is { Count: 0 })
    {
        logger.Warning("No jail rules configured in {0}.", jailsPath);
    }

    var builder = new HostBuilder()
        .ConfigureServices((hostContext, services) =>
        {
            services.AddSingleton(options);
            services.AddSingleton<IOptions<JailerOptions>>(new OptionsWrapper<JailerOptions>(options));
            services.AddSingleton<IHostedService, HostService>();
        });

    await builder.RunConsoleAsync();
}
catch (Exception ex)
{
    logger.Error("Application terminated unexpectedly {0}", ex);
    return 1;
}

return 0;
