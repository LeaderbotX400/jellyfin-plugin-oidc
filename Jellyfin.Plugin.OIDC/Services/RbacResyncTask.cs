using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Configuration;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

public class RbacResyncTask : IScheduledTask
{
    // 0 = idle, 1 = running. Use Interlocked to guard against concurrent manual + interval triggers.
    private static int _runState = 0;

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly OidcUserStore _userStore;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<RbacResyncTask> _logger;

    public RbacResyncTask(
        IServiceScopeFactory scopeFactory,
        OidcUserStore userStore,
        IPluginConfigProvider configProvider,
        ILogger<RbacResyncTask> logger)
    {
        _scopeFactory = scopeFactory;
        _userStore = userStore;
        _configProvider = configProvider;
        _logger = logger;
    }

    public string Name => "OIDC SSO Re-sync";
    public string Key => "OidcRbacResync";
    public string Description => "Re-applies current OIDC role and entitlement mappings to all SSO-authenticated users. Run after changing role mappings to propagate without requiring re-login.";
    public string Category => "OIDC SSO";

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
        // Re-entry guard: only one concurrent execution allowed.
        if (Interlocked.CompareExchange(ref _runState, 1, 0) != 0)
        {
            _logger.LogInformation("RBAC resync already running; skipping");
            return;
        }

        try
        {
            await RunAsync(progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Exchange(ref _runState, 0);
        }
    }

    private async Task RunAsync(IProgress<double> progress, CancellationToken cancellationToken)
    {
        var records = await _userStore.GetAllAsync().ConfigureAwait(false);
        if (records.Count == 0)
        {
            _logger.LogInformation("OIDC SSO re-sync: no stored users, nothing to do");
            progress.Report(100);
            return;
        }

        // Snapshot config once so all users are processed with identical rules.
        // Mid-run config changes intentionally take effect only on the next run.
        PluginConfiguration configSnapshot = _configProvider.GetConfiguration();

        _logger.LogInformation("OIDC SSO re-sync: processing {Count} user(s)", records.Count);

        using var scope = _scopeFactory.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<RbacService>();

        int successCount = 0;
        int failureCount = 0;
        int done = 0;
        bool cancelled = false;

        foreach (var record in records)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                cancelled = true;
                break;
            }

            try
            {
                await rbacService.ApplyRoleMappingsAsync(
                    record.UserId,
                    record.Roles,
                    record.Entitlements,
                    record.ProviderId,
                    configSnapshot).ConfigureAwait(false);

                successCount++;
                _logger.LogDebug("Re-synced RBAC for user {Username}", record.Username);
            }
            catch (Exception ex)
            {
                failureCount++;
                _logger.LogWarning(ex, "RBAC re-sync failed for user {Username}", record.Username);
            }

            done++;
            progress.Report((double)done / records.Count * 100);
        }

        if (cancelled)
        {
            _logger.LogInformation(
                "OIDC SSO re-sync cancelled after {Done}/{Total} user(s): {Success} updated, {Failure} failed",
                done, records.Count, successCount, failureCount);

            await rbacService.LogActivityAsync(
                $"OIDC SSO re-sync cancelled: {successCount} updated, {failureCount} failed (processed {done}/{records.Count})",
                "OidcResyncCancelled",
                Guid.Empty,
                null,
                LogLevel.Warning).ConfigureAwait(false);

            return;
        }

        string summary = $"OIDC SSO resync complete: {successCount} updated, {failureCount} failed";

        if (failureCount > 0)
        {
            _logger.LogWarning("{Summary}", summary);
            await rbacService.LogActivityAsync(
                summary,
                "OidcResyncCompleted",
                Guid.Empty,
                null,
                LogLevel.Warning).ConfigureAwait(false);
        }
        else
        {
            _logger.LogInformation("{Summary}", summary);
            await rbacService.LogActivityAsync(
                summary,
                "OidcResyncCompleted",
                Guid.Empty,
                null,
                LogLevel.Information).ConfigureAwait(false);
        }
    }
}
