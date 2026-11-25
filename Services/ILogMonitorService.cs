

namespace Jailer.Services
{
    public interface ILogMonitorService
    {
        IEnumerable<string> GetViolatedIps();
        Task<IEnumerable<string>> GetExpiredIpsAsync();
        void MarkAsJailed(string ip);
        TimeSpan JailDuration { get; }
    }
}
