using DepRadar.Application.Analysis;
using DepRadar.Application.Ecosystems;
using DepRadar.Application.Policy;
using DepRadar.Application.Projects;
using DepRadar.Application.Risk;
using DepRadar.Application.Sarif;
using DepRadar.Application.Sbom;
using DepRadar.Domain.ValueObjects;
using Microsoft.Extensions.DependencyInjection;

namespace DepRadar.Cli;

/// <summary>
/// The <c>scan</c> command: resolves and scores a package or whole project entirely
/// in-process (no server, no database), then gates the result against a policy and
/// returns a CI-friendly exit code.
/// </summary>
internal static class ScanCommand
{
    /// <summary>Runs <c>scan</c> with the arguments after the verb.</summary>
    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        if (!CliOptions.TryParse(args, out var options, out var error))
        {
            await Console.Error.WriteLineAsync(error);
            await Console.Error.WriteLineAsync();
            await Console.Error.WriteLineAsync(CliOptions.Usage);
            return ExitCodes.Usage;
        }

        if (!TryResolveTargets(options!.Target, out var targets, out var targetError))
        {
            await Console.Error.WriteLineAsync(targetError);
            return ExitCodes.Usage;
        }

        // Deliberately NOT disposed: this is a short-lived process, and disposing the
        // provider (killing the HttpClients) while HybridCache still has queued
        // background fetches turns their synchronous ObjectDisposedException into an
        // unhandled ThreadPool exception — a hard SIGABRT. Process exit cleans up.
        var provider = CliHost.BuildProvider();
        var scope = provider.CreateAsyncScope();
        var analyzer = scope.ServiceProvider.GetRequiredService<ProjectAnalyzer>();

        // Typos happen where a human writes the name — the direct targets.
        var warnings = targets
            .Select(target => (Name: target, Target: Lookalike.FindTarget(target.ToLowerInvariant(), KnownPackages.NuGet)))
            .Where(pair => pair.Target is not null)
            .Select(pair => $"'{pair.Name}' looks like a typo of '{pair.Target}' — possible typosquat.")
            .ToList();

        var assessments = new List<GraphAssessment>();
        var unresolved = new List<string>();
        foreach (var target in targets)
        {
            var assessment = await analyzer.AnalyzeAsync(PackageId.Create(target), pinnedVersion: null, cancellationToken);
            if (assessment is null)
            {
                unresolved.Add(target);
            }
            else
            {
                assessments.Add(assessment);
            }
        }

        if (assessments.Count == 0)
        {
            await Console.Error.WriteLineAsync($"Nothing could be resolved from '{options.Target}'.");
            return ExitCodes.Usage;
        }

        var graph = GraphMerge.Union(assessments);
        if (!TryResolvePolicy(options, out var policy, out var policyError))
        {
            await Console.Error.WriteLineAsync(policyError);
            return ExitCodes.Usage;
        }

        var outcome = PolicyEvaluator.Evaluate(graph, policy!);

        if (options.Json)
        {
            ConsoleReport.WriteJson(graph, outcome, unresolved, warnings);
        }
        else
        {
            ConsoleReport.WriteText(graph, outcome, unresolved, warnings);
        }

        if (options.SbomPath is { } sbomPath)
        {
            await File.WriteAllTextAsync(sbomPath, CycloneDxBuilder.Build(graph, DateTimeOffset.UtcNow), cancellationToken);
            if (!options.Json)
            {
                Console.WriteLine($"  SBOM written to {sbomPath}");
            }
        }

        if (options.SarifPath is { } sarifPath)
        {
            await File.WriteAllTextAsync(sarifPath, SarifBuilder.Build(graph, options.Target), cancellationToken);
            if (!options.Json)
            {
                Console.WriteLine($"  SARIF written to {sarifPath}");
            }
        }

        return outcome.Passed ? ExitCodes.Ok : ExitCodes.PolicyViolation;
    }

    /// <summary>The gate resolution is shared with every ecosystem verb (see <see cref="CliPolicy"/>).</summary>
    private static bool TryResolvePolicy(CliOptions options, out RiskPolicy? policy, out string? error) =>
        CliPolicy.TryResolve(options.PolicyPath, options.ToPolicy(), out policy, out error);

    /// <summary>A package id scans one root; an existing project file scans its direct dependencies.</summary>
    private static bool TryResolveTargets(string target, out IReadOnlyList<string> packages, out string? error)
    {
        error = null;

        if (File.Exists(target))
        {
            try
            {
                packages = ProjectFileParser.ParseDirectPackages(File.ReadAllText(target));
                if (packages.Count == 0)
                {
                    error = $"No package references found in '{target}'.";
                    return false;
                }

                return true;
            }
            catch (FormatException ex)
            {
                packages = [];
                error = $"Could not parse '{target}': {ex.Message}";
                return false;
            }
        }

        try
        {
            // Validate the id up front so a typo fails as usage, not mid-run.
            _ = PackageId.Create(target);
            packages = [target];
            return true;
        }
        catch (ArgumentException ex)
        {
            packages = [];
            error = $"'{target}' is neither a file nor a valid package id: {ex.Message}";
            return false;
        }
    }

}
