using System.Globalization;
using System.Text;
using DepRadar.Application.Abstractions;
using DepRadar.Application.Analysis;
using DepRadar.Application.Ecosystems;
using DepRadar.Application.Projects;
using DepRadar.Application.Remediation;
using DepRadar.Domain.ValueObjects;
using Microsoft.Extensions.DependencyInjection;

namespace DepRadar.Cli;

/// <summary>
/// The <c>fix</c> command: finds vulnerable <em>direct</em> dependencies in a manifest
/// (.csproj/props, package.json, requirements.txt), bumps each to its minimal safe
/// version, and either writes the file in place or opens a pull request with the change.
/// </summary>
internal static class FixCommand
{
    /// <summary>The usage banner for <c>fix</c>.</summary>
    public const string Usage =
        "Usage: depradar fix <.csproj | Directory.Packages.props | package.json | requirements.txt | Cargo.toml | go.mod> [--open-pr] [--repo owner/name] [--base main] [--dry-run]";

    /// <summary>Runs <c>fix</c> with the arguments after the verb.</summary>
    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        var openPr = args.Contains("--open-pr");
        var dryRun = args.Contains("--dry-run");
        var repo = OptionValue(args, "--repo") ?? Environment.GetEnvironmentVariable("GITHUB_REPOSITORY");
        var baseBranch = OptionValue(args, "--base") ?? "main";
        var manifestPath = args.FirstOrDefault(arg => !arg.StartsWith('-'));

        if (manifestPath is null || !File.Exists(manifestPath))
        {
            await Console.Error.WriteLineAsync(manifestPath is null ? Usage : $"File not found: {manifestPath}");
            return ExitCodes.Usage;
        }

        var content = await File.ReadAllTextAsync(manifestPath, cancellationToken);

        // Deliberately NOT disposed: this is a short-lived process, and disposing the
        // provider (killing the HttpClients) while HybridCache still has queued
        // background fetches turns their synchronous ObjectDisposedException into an
        // unhandled ThreadPool exception — a hard SIGABRT. Process exit cleans up.
        var provider = CliHost.BuildProvider();
        var scope = provider.CreateAsyncScope();

        ManifestPatch patch;
        try
        {
            patch = await ResolvePatchAsync(scope.ServiceProvider, manifestPath, content, cancellationToken);
        }
        catch (FormatException exception)
        {
            await Console.Error.WriteLineAsync($"Could not parse '{manifestPath}': {exception.Message}");
            return ExitCodes.Usage;
        }

        if (patch.Applied.Count == 0)
        {
            Console.WriteLine("No vulnerable direct dependencies with a known fix. Nothing to do.");
            return ExitCodes.Ok;
        }

        Console.WriteLine($"Fixable vulnerable dependencies in {manifestPath}:");
        foreach (var bump in patch.Applied)
        {
            Console.WriteLine($"  {bump.Package}: {bump.FromVersion} -> {bump.ToVersion}");
        }

        if (dryRun)
        {
            return ExitCodes.Ok;
        }

        if (openPr)
        {
            return await OpenPullRequestAsync(scope.ServiceProvider, repo, baseBranch, manifestPath, patch, cancellationToken);
        }

        await File.WriteAllTextAsync(manifestPath, patch.Content, cancellationToken);
        Console.WriteLine($"Patched {manifestPath} in place.");
        return ExitCodes.Ok;
    }

    /// <summary>Dispatches by manifest flavor: package.json → npm, *.txt → PyPI, else NuGet XML.</summary>
    private static async Task<ManifestPatch> ResolvePatchAsync(
        IServiceProvider services,
        string manifestPath,
        string content,
        CancellationToken cancellationToken)
    {
        var fileName = Path.GetFileName(manifestPath);

        if (string.Equals(fileName, "package.json", StringComparison.OrdinalIgnoreCase))
        {
            var scanner = services.GetRequiredService<INpmScanner>();
            var bumps = await EcosystemFix.ResolveBumpsAsync(
                NpmManifest.ParseDependencies(content),
                isPatchable: static _ => true, // every registry range can be rewritten in place
                scanner.ScanAsync,
                scanner.ListVersionsAsync,
                EcosystemFix.WholeGraphClean,
                cancellationToken);
            return NpmManifestPatcher.Apply(content, bumps);
        }

        if (fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
        {
            var scanner = services.GetRequiredService<IPyPiScanner>();
            var bumps = await EcosystemFix.ResolveBumpsAsync(
                RequirementsFile.Parse(content),
                // Only an exact == pin has a single unambiguous version to replace.
                isPatchable: static dependency => dependency.Specifier.StartsWith("==", StringComparison.Ordinal)
                    && !dependency.Specifier.Contains('*'),
                scanner.ScanAsync,
                scanner.ListVersionsAsync,
                EcosystemFix.WholeGraphClean,
                cancellationToken);
            return RequirementsPatcher.Apply(content, bumps);
        }

        if (string.Equals(fileName, "Cargo.toml", StringComparison.OrdinalIgnoreCase))
        {
            var scanner = services.GetRequiredService<ICargoScanner>();
            var bumps = await EcosystemFix.ResolveBumpsAsync(
                CargoManifest.ParseDependencies(content),
                isPatchable: static _ => true, // every parsed form carries one rewritable requirement
                scanner.ScanAsync,
                scanner.ListVersionsAsync,
                EcosystemFix.WholeGraphClean,
                cancellationToken);
            return CargoManifestPatcher.Apply(content, bumps);
        }

        if (string.Equals(fileName, "go.mod", StringComparison.OrdinalIgnoreCase))
        {
            var scanner = services.GetRequiredService<IGoScanner>();
            var bumps = await EcosystemFix.ResolveBumpsAsync(
                GoMod.ParseRequires(content),
                isPatchable: static _ => true, // go.mod requirements are exact by definition
                scanner.ScanAsync,
                scanner.ListVersionsAsync,
                // The declared go.mod graph pins historical minimums MVS never installs,
                // so the whole-graph bar is unsatisfiable — fix the module itself.
                EcosystemFix.RootClean,
                cancellationToken);
            return GoModPatcher.Apply(content, bumps);
        }

        var analyzer = services.GetRequiredService<ProjectAnalyzer>();
        var finder = services.GetRequiredService<SafeUpgradeFinder>();
        var references = ProjectFileParser.ParseReferences(content);
        return ManifestPatcher.Apply(content, await ResolveNuGetBumpsAsync(references, analyzer, finder, cancellationToken));
    }

    private static async Task<Dictionary<string, string>> ResolveNuGetBumpsAsync(
        IReadOnlyList<ManifestReference> references,
        ProjectAnalyzer analyzer,
        SafeUpgradeFinder finder,
        CancellationToken cancellationToken)
    {
        var bumps = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var reference in references)
        {
            if (!SemVer.TryParse(reference.Version, out var version))
            {
                continue;
            }

            var package = PackageId.Create(reference.Id);

            // A direct dependency needs fixing if anything in *its* graph is vulnerable —
            // the package itself or a transitive. Bumping the direct one to a clean-graph
            // version is the parent-bump fix for transitive advisories.
            var graph = await analyzer.AnalyzeAsync(package, version, cancellationToken);
            if (graph is null || graph.Nodes.All(node => node.Input.Vulnerabilities.Count == 0))
            {
                continue;
            }

            if (await finder.FindMinimalCleanVersionAsync(package, version, cancellationToken) is { } safe)
            {
                bumps[reference.Id] = safe;
            }
            else
            {
                await Console.Error.WriteLineAsync($"  {reference.Id}: vulnerable, but no newer version resolves a clean graph (consider replacing it).");
            }
        }

        return bumps;
    }

    private static async Task<int> OpenPullRequestAsync(
        IServiceProvider services,
        string? repo,
        string baseBranch,
        string manifestPath,
        ManifestPatch patch,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(repo))
        {
            await Console.Error.WriteLineAsync("--open-pr needs a repository: pass --repo owner/name or set GITHUB_REPOSITORY.");
            return ExitCodes.Usage;
        }

        var opener = services.GetRequiredService<IPullRequestOpener>();
        var branch = string.Create(CultureInfo.InvariantCulture, $"depradar/fix-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}");
        var (title, body) = Describe(patch.Applied);

        var url = await opener.OpenAsync(
            new PullRequestRequest(repo, baseBranch, branch, manifestPath, patch.Content, title, body),
            cancellationToken);

        if (url is null)
        {
            await Console.Error.WriteLineAsync("No GitHub token configured — set GITHUB_TOKEN to open a pull request.");
            return ExitCodes.Usage;
        }

        Console.WriteLine($"Opened pull request: {url}");
        return ExitCodes.Ok;
    }

    private static (string Title, string Body) Describe(IReadOnlyList<PackageBump> bumps)
    {
        var title = string.Create(
            CultureInfo.InvariantCulture,
            $"DepRadar: upgrade {bumps.Count} vulnerable dependenc{(bumps.Count == 1 ? "y" : "ies")}");

        var body = new StringBuilder();
        body.Append("DepRadar found and fixed ").Append(bumps.Count.ToString(CultureInfo.InvariantCulture))
            .AppendLine(" vulnerable direct dependenc(y/ies):").AppendLine();
        foreach (var bump in bumps)
        {
            body.Append("- **").Append(bump.Package).Append("** ").Append(bump.FromVersion).Append(" → ").AppendLine(bump.ToVersion);
        }

        body.AppendLine().AppendLine("_Opened automatically by DepRadar._");
        return (title, body.ToString());
    }

    private static string? OptionValue(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
