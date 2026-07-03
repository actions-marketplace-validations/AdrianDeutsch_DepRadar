using DepRadar.Application.Analysis;
using DepRadar.Application.Diff;
using DepRadar.Domain.ValueObjects;
using Microsoft.Extensions.DependencyInjection;

namespace DepRadar.Cli;

/// <summary>
/// The <c>diff</c> command: resolves a package at two versions and reports how the
/// transitive graph and risk change — the "what do I take on if I upgrade?" question.
/// </summary>
internal static class DiffCommand
{
    /// <summary>The usage banner for <c>diff</c>.</summary>
    public const string Usage = "Usage: depradar diff <package-id> <from-version> <to-version> [--json]";

    /// <summary>Runs <c>diff</c> with the arguments after the verb.</summary>
    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        var json = args.Contains("--json");
        var positional = args.Where(arg => !arg.StartsWith('-')).ToList();
        if (positional.Count != 3)
        {
            await Console.Error.WriteLineAsync(Usage);
            return ExitCodes.Usage;
        }

        if (!SemVer.TryParse(positional[1], out _) || !SemVer.TryParse(positional[2], out _))
        {
            await Console.Error.WriteLineAsync("Both versions must be valid (e.g. 12.0.3).");
            return ExitCodes.Usage;
        }

        // Deliberately NOT disposed: this is a short-lived process, and disposing the
        // provider (killing the HttpClients) while HybridCache still has queued
        // background fetches turns their synchronous ObjectDisposedException into an
        // unhandled ThreadPool exception — a hard SIGABRT. Process exit cleans up.
        var provider = CliHost.BuildProvider();
        var scope = provider.CreateAsyncScope();
        var analyzer = scope.ServiceProvider.GetRequiredService<ProjectAnalyzer>();

        var package = PackageId.Create(positional[0]);
        var fromGraph = await analyzer.AnalyzeAsync(package, SemVer.Parse(positional[1]), cancellationToken);
        var toGraph = await analyzer.AnalyzeAsync(package, SemVer.Parse(positional[2]), cancellationToken);
        if (fromGraph is null || toGraph is null)
        {
            await Console.Error.WriteLineAsync($"Could not resolve {positional[0]} at both {positional[1]} and {positional[2]}.");
            return ExitCodes.Usage;
        }

        var diff = GraphDiffer.Diff(fromGraph, toGraph);
        if (json)
        {
            DiffReport.WriteJson(diff);
        }
        else
        {
            DiffReport.WriteText(diff);
        }

        return ExitCodes.Ok;
    }
}
