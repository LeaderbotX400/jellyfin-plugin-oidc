using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

public class RbacResyncTask : IScheduledTask
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly OidcUserStore _userStore;
    private readonly ILogger<RbacResyncTask> _logger;

    public RbacResyncTask(
        IServiceScopeFactory scopeFactory,
        OidcUserStore userStore,
        ILogger<RbacResyncTask> logger)
    {
        _scopeFactory = scopeFactory;
        _userStore = userStore;
        _logger = logger;
    }

    public string Name => "OIDC RBAC Re-sync";
    public string Key => "OidcRbacResync";
    public string Description => "Re-applies current OIDC role and entitlement mappings to all SSO-authenticated users. Run after changing role mappings to propagate without requiring re-login.";
    public string Category => "OIDC RBAC";

    public IEnumerable<TaskTriggerInfo> GetDefaultTriggers()
    {
        yield return new TaskTriggerInfo
        {
            Type = TaskTriggerInfoType.IntervalTrigger,
            IntervalTicks = TimeSpan.FromHours(1).Ticks
        };
    }

    public async Task ExecuteAsync(IProgress<double> progress, CancellationToken cancellationToken)
    {
        var records = await _userStore.GetAllAsync().ConfigureAwait(false);
        if (records.Count == 0)
        {
            _logger.LogInformation("OIDC RBAC re-sync: no stored users, nothing to do");
            progress.Report(100);
            return;
        }

        _logger.LogInformation("OIDC RBAC re-sync: processing {Count} user(s)", records.Count);

        using var scope = _scopeFactory.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<RbacService>();

        int done = 0;
        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await rbacService.ApplyRoleMappingsAsync(
                    record.UserId,
                    record.Roles,
                    record.Entitlements,
                    record.ProviderId).ConfigureAwait(false);

                _logger.LogDebug("Re-synced RBAC for user {Username}", record.Username);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "RBAC re-sync failed for user {Username}", record.Username);
            }

            done++;
            progress.Report((double)done / records.Count * 100);
        }

        _logger.LogInformation("OIDC RBAC re-sync complete: {Count} user(s) processed", done);

        using var logScope = _scopeFactory.CreateScope();
        var rbac = logScope.ServiceProvider.GetRequiredService<RbacService>();
        await rbac.LogActivityAsync(
            $"OIDC RBAC re-sync completed: {done} user(s) updated",
            "OidcResyncCompleted",
            Guid.Empty,
            null,
            Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);
    }
}
