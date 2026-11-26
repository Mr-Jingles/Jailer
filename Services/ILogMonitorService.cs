

namespace Jailer.Services
{
    public interface ILogMonitorService
    {
        /// <summary>Invoked immediately when an IP reaches its attempt threshold.</summary>
        Action<string, Jailer.Models.JailRule>? ViolationDetected { get; set; }

        Task StartMonitoringAsync(CancellationToken ct);
        IEnumerable<string> GetViolatedIps();
        Task<IEnumerable<JailedIp>> GetExpiredIpsAsync();

        /// <summary>Snapshot of the current jail state, grouped by jail name.</summary>
        Dictionary<string, List<(string Ip, DateTime ExpiresUtc)>> GetJailState();

        void MarkAsJailed(string ip);
        void MarkAsJailed(string ip, Jailer.Models.JailRule? rule);
        TimeSpan JailDuration { get; }
    }
}
