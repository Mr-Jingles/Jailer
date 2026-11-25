

namespace Jailer.Services
{
    public interface ILogMonitorService
    {
        Task StartMonitoringAsync(CancellationToken ct);
        IEnumerable<string> GetViolatedIps();
        Task<IEnumerable<string>> GetExpiredIpsAsync();
        void MarkAsJailed(string ip);
        void MarkAsJailed(string ip, Jailer.Models.JailRule? rule);
        TimeSpan JailDuration { get; }
    }
}
