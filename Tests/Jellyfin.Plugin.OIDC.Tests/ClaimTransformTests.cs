using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

// ── Minimal fake logger that records calls ────────────────────────────────────

public sealed class FakeLogger : ILogger
{
    private readonly List<(LogLevel Level, string Message)> _entries = new();

    public IReadOnlyList<(LogLevel Level, string Message)> Entries => _entries;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        _entries.Add((logLevel, formatter(state, exception)));
    }

    public bool HasEntry(LogLevel level, string containing) =>
        _entries.Any(e => e.Level == level && e.Message.Contains(containing, StringComparison.OrdinalIgnoreCase));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

public class ClaimTransformTests
{
    [Fact]
    public void ApplyTransforms_NullTransforms_ReturnsSameValues()
    {
        var values = new[] { "admin", "viewer" };
        var result = ClaimParser.ApplyTransforms(values, null);
        Assert.Equal(values, result);
    }

    [Fact]
    public void ApplyTransforms_EmptyTransforms_ReturnsSameValues()
    {
        var values = new[] { "admin", "viewer" };
        var result = ClaimParser.ApplyTransforms(values, new List<ClaimTransform>());
        Assert.Equal(values, result);
    }

    [Fact]
    public void ApplyTransforms_MatchingRule_ReplacesValue()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "cn=admins,dc=org", ToValue = "admin" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "cn=admins,dc=org", "viewer" }, transforms);
        Assert.Equal(new[] { "admin", "viewer" }, result);
    }

    [Fact]
    public void ApplyTransforms_EmptyToValue_DropsValue()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "legacy-role", ToValue = "" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin", "legacy-role", "viewer" }, transforms);
        Assert.Equal(new[] { "admin", "viewer" }, result);
    }

    [Fact]
    public void ApplyTransforms_CaseInsensitiveMatch()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "ADMIN", ToValue = "administrator" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin" }, transforms);
        Assert.Equal(new[] { "administrator" }, result);
    }

    [Fact]
    public void ApplyTransforms_UnmatchedValues_PassThrough()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "old-role", ToValue = "new-role" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin", "viewer" }, transforms);
        Assert.Equal(new[] { "admin", "viewer" }, result);
    }

    [Fact]
    public void ApplyTransforms_FirstMatchWins()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "admin", ToValue = "superadmin" },
            new() { FromValue = "admin", ToValue = "megaadmin" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin" }, transforms);
        Assert.Equal(new[] { "superadmin" }, result);
    }

    // ── Logging tests ──────────────────────────────────────────────────────────

    [Fact]
    public void ApplyTransforms_LogsInfoOnApply()
    {
        var logger = new FakeLogger();
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "cn=admins,dc=org", ToValue = "admin" }
        };

        ClaimParser.ApplyTransforms(new[] { "cn=admins,dc=org" }, transforms, "myprovider", logger);

        Assert.True(logger.HasEntry(LogLevel.Information, "transform applied"),
            "Expected an Info log for the applied transform");
        // Log must reference the transform rule names, not opaque token data
        Assert.True(logger.HasEntry(LogLevel.Information, "cn=admins,dc=org"),
            "Log should contain FromValue");
        Assert.True(logger.HasEntry(LogLevel.Information, "admin"),
            "Log should contain ToValue");
        Assert.True(logger.HasEntry(LogLevel.Information, "myprovider"),
            "Log should contain provider id");
    }

    [Fact]
    public void ApplyTransforms_LogsWarningOnDrop()
    {
        var logger = new FakeLogger();
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "legacy-role", ToValue = "" }
        };

        ClaimParser.ApplyTransforms(new[] { "legacy-role" }, transforms, "myprovider", logger);

        Assert.True(logger.HasEntry(LogLevel.Warning, "dropped"),
            "Expected a Warning log for the dropped role");
        Assert.True(logger.HasEntry(LogLevel.Warning, "legacy-role"),
            "Log should contain the dropped role identifier (FromValue)");
    }

    [Fact]
    public void ApplyTransforms_WhitespaceToValue_DropsAndLogsWarning()
    {
        var logger = new FakeLogger();
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "test-role", ToValue = "   " }
        };

        var result = ClaimParser.ApplyTransforms(new[] { "test-role" }, transforms, "p", logger);

        Assert.Empty(result);
        Assert.True(logger.HasEntry(LogLevel.Warning, "dropped"));
    }

    [Fact]
    public void ApplyTransforms_NoLogger_DoesNotThrow()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "x", ToValue = "y" }
        };

        // Should work fine with null logger (no-op)
        var result = ClaimParser.ApplyTransforms(new[] { "x" }, transforms, "p", null);
        Assert.Equal(new[] { "y" }, result);
    }

    [Fact]
    public void ApplyTransforms_UnmatchedValue_DoesNotLog()
    {
        var logger = new FakeLogger();
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "other", ToValue = "y" }
        };

        ClaimParser.ApplyTransforms(new[] { "admin" }, transforms, "p", logger);

        // Unmatched values pass through silently
        Assert.Empty(logger.Entries);
    }
}
