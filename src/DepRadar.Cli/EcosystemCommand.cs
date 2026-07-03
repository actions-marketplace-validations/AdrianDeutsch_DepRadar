using System.Collections.Frozen;
using DepRadar.Application.Ecosystems;
using DepRadar.Application.Policy;
using DepRadar.Application.Risk;
using DepRadar.Application.Sarif;
using DepRadar.Application.Sbom;
using DepRadar.Domain.Risk;
using DepRadar.Domain.ValueObjects;
using Microsoft.Extensions.DependencyInjection;

namespace DepRadar.Cli;

/// <summary>How one ecosystem plugs into the shared <see cref="EcosystemCommand"/>.</summary>
/// <param name="RegistryLabel">Registry name for the not-found message, e.g. <c>"the npm registry"</c>.</param>
/// <param name="ParseManifest">Parses the ecosystem's manifest into direct dependencies.</param>
/// <param name="ResolveScanner">Resolves the ecosystem's scan delegate from the DI scope.</param>
/// <param name="IsLockfile">Whether a file name is this ecosystem's lockfile.</param>
/// <param name="ParseLockfile">Parses the ecosystem's lockfile into exact installed packages.</param>
/// <param name="ResolveLockScanner">Resolves the ecosystem's lockfile-scan delegate from the DI scope.</param>
/// <param name="FindLookalike">The well-known package a name looks like a typo of, or null.</param>
internal sealed record EcosystemCli(
    string RegistryLabel,
    Func<string, IReadOnlyList<ManifestDependency>> ParseManifest,
    Func<IServiceProvider, Func<string, string?, CancellationToken, Task<GraphAssessment?>>> ResolveScanner,
    Func<string, bool> IsLockfile,
    Func<string, IReadOnlyList<LockedPackage>> ParseLockfile,
    Func<IServiceProvider, Func<IReadOnlyList<LockedPackage>, CancellationToken, Task<GraphAssessment?>>> ResolveLockScanner,
    Func<string, string?> FindLookalike);

/// <summary>
/// The shared engine behind <c>depradar npm</c> and <c>depradar pypi</c>: scans a single
/// package (optionally at a version/range) or a whole manifest file, then reuses the same
/// renderer, policy gate and SBOM/SARIF writers as the NuGet <c>scan</c> command.
/// </summary>
internal static class EcosystemCommand
{
    /// <summary>Runs the command with the arguments after the verb.</summary>
    public static async Task<int> RunAsync(EcosystemCli cli, string usage, string[] args, CancellationToken cancellationToken)
    {
        var json = false;
        var failOn = RiskLevel.High;
        string? policyPath = null;
        string? sbomPath = null;
        string? sarifPath = null;
        var positional = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--json":
                    json = true;
                    break;

                case "--fail-on":
                    if (i + 1 >= args.Length || !Enum.TryParse(args[++i], ignoreCase: true, out failOn))
                    {
                        await Console.Error.WriteLineAsync($"Invalid --fail-on value. Expected one of: {string.Join(", ", Enum.GetNames<RiskLevel>())}.");
                        return ExitCodes.Usage;
                    }

                    break;

                case "--policy" when i + 1 < args.Length:
                    policyPath = args[++i];
                    break;

                case "--sbom" when i + 1 < args.Length:
                    sbomPath = args[++i];
                    break;

                case "--sarif" when i + 1 < args.Length:
                    sarifPath = args[++i];
                    break;

                default:
                    if (args[i].StartsWith('-'))
                    {
                        await Console.Error.WriteLineAsync($"Unknown option '{args[i]}'.");
                        return ExitCodes.Usage;
                    }

                    positional.Add(args[i]);
                    break;
            }
        }

        if (positional.Count == 0)
        {
            await Console.Error.WriteLineAsync(usage);
            return ExitCodes.Usage;
        }

        // Deliberately NOT disposed: this is a short-lived process, and disposing the
        // provider (killing the HttpClients) while HybridCache still has queued
        // background fetches turns their synchronous ObjectDisposedException into an
        // unhandled ThreadPool exception — a hard SIGABRT. Process exit cleans up.
        var provider = CliHost.BuildProvider();
        var scope = provider.CreateAsyncScope();

        GraphAssessment graph;
        var unresolved = new List<string>();
        var warnings = new List<string>();

        if (File.Exists(positional[0]) && cli.IsLockfile(Path.GetFileName(positional[0])))
        {
            var (locked, lockError) = await ScanLockfileAsync(cli, scope.ServiceProvider, positional, cancellationToken);
            if (locked is null)
            {
                await Console.Error.WriteLineAsync(lockError);
                return ExitCodes.Usage;
            }

            graph = locked;
        }
        else
        {
            if (!TryResolveTargets(cli, positional, out var targets, out var targetError))
            {
                await Console.Error.WriteLineAsync(targetError);
                return ExitCodes.Usage;
            }

            // Typos happen where a human writes the name — the direct targets — so the
            // lookalike check runs exactly there (never on transitive/locked packages).
            warnings.AddRange(targets
                .Select(target => (target.Name, Target: cli.FindLookalike(target.Name)))
                .Where(pair => pair.Target is not null)
                .Select(pair => $"'{pair.Name}' looks like a typo of '{pair.Target}' — possible typosquat."));

            var scan = cli.ResolveScanner(scope.ServiceProvider);
            var assessments = new List<GraphAssessment>();
            foreach (var (name, specifier) in targets)
            {
                var assessment = await scan(name, specifier, cancellationToken);
                if (assessment is null)
                {
                    unresolved.Add(specifier is null ? name : $"{name} {specifier}");
                }
                else
                {
                    assessments.Add(assessment);
                }
            }

            if (assessments.Count == 0)
            {
                foreach (var warning in warnings)
                {
                    await Console.Error.WriteLineAsync($"! {warning}");
                }

                await Console.Error.WriteLineAsync($"Nothing from '{positional[0]}' could be resolved on {cli.RegistryLabel}.");
                return ExitCodes.Usage;
            }

            graph = GraphMerge.Union(assessments);
        }
        // A committed depradar.json governs every ecosystem, not just the NuGet scan.
        var fallback = new RiskPolicy(failOn, AllowDeprecated: true, FrozenSet<LicenseCategory>.Empty);
        if (!CliPolicy.TryResolve(policyPath, fallback, out var policy, out var policyError))
        {
            await Console.Error.WriteLineAsync(policyError);
            return ExitCodes.Usage;
        }

        var outcome = PolicyEvaluator.Evaluate(graph, policy!);

        if (json)
        {
            ConsoleReport.WriteJson(graph, outcome, unresolved, warnings);
        }
        else
        {
            ConsoleReport.WriteText(graph, outcome, unresolved, warnings);
        }

        if (sbomPath is not null)
        {
            await File.WriteAllTextAsync(sbomPath, CycloneDxBuilder.Build(graph, DateTimeOffset.UtcNow), cancellationToken);
            if (!json)
            {
                Console.WriteLine($"  SBOM written to {sbomPath}");
            }
        }

        if (sarifPath is not null)
        {
            await File.WriteAllTextAsync(sarifPath, SarifBuilder.Build(graph, positional[0]), cancellationToken);
            if (!json)
            {
                Console.WriteLine($"  SARIF written to {sarifPath}");
            }
        }

        return outcome.Passed ? ExitCodes.Ok : ExitCodes.PolicyViolation;
    }

    /// <summary>Scans a lockfile's exact installed packages; returns (null, error) on a usage problem.</summary>
    private static async Task<(GraphAssessment? Graph, string? Error)> ScanLockfileAsync(
        EcosystemCli cli,
        IServiceProvider services,
        List<string> positional,
        CancellationToken cancellationToken)
    {
        if (positional.Count > 1)
        {
            return (null, "A lockfile scan does not take a version argument.");
        }

        IReadOnlyList<LockedPackage> locked;
        try
        {
            locked = cli.ParseLockfile(await File.ReadAllTextAsync(positional[0], cancellationToken));
        }
        catch (FormatException exception)
        {
            return (null, $"Could not parse '{positional[0]}': {exception.Message}");
        }

        if (locked.Count == 0)
        {
            return (null, $"No locked packages found in '{positional[0]}'.");
        }

        var graph = await cli.ResolveLockScanner(services)(locked, cancellationToken);
        if (graph is null)
        {
            return (null, $"No entry of '{positional[0]}' has a scannable version.");
        }

        if (graph.Nodes.Count < locked.Count)
        {
            await Console.Error.WriteLineAsync($"  note: {locked.Count - graph.Nodes.Count} lockfile entr(y/ies) skipped (unparseable version).");
        }

        return (graph, null);
    }

    /// <summary>A package name scans one root; an existing manifest file scans its direct dependencies.</summary>
    private static bool TryResolveTargets(
        EcosystemCli cli,
        List<string> positional,
        out IReadOnlyList<(string Name, string? Specifier)> targets,
        out string? error)
    {
        error = null;
        targets = [];

        if (File.Exists(positional[0]))
        {
            if (positional.Count > 1)
            {
                error = "A manifest scan does not take a version argument.";
                return false;
            }

            try
            {
                var dependencies = cli.ParseManifest(File.ReadAllText(positional[0]));
                if (dependencies.Count == 0)
                {
                    error = $"No dependencies found in '{positional[0]}'.";
                    return false;
                }

                targets = dependencies
                    .Select(d => (d.Name, string.IsNullOrWhiteSpace(d.Specifier) ? null : d.Specifier))
                    .ToList();
                return true;
            }
            catch (FormatException exception)
            {
                error = $"Could not parse '{positional[0]}': {exception.Message}";
                return false;
            }
        }

        targets = [(positional[0], positional.Count > 1 ? positional[1] : null)];
        return true;
    }
}
