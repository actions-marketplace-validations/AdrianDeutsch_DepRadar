using System.Text.RegularExpressions;
using DepRadar.Application.Projects;

namespace DepRadar.Application.Ecosystems;

/// <summary>
/// Applies version bumps to a <c>Cargo.toml</c>'s text — the Cargo counterpart of
/// <see cref="ManifestPatcher"/>. A targeted line edit keeps formatting and comments
/// intact. Pure.
/// </summary>
/// <remarks>
/// Rewrites the same three forms <see cref="CargoManifest"/> parses: <c>name = "1.0"</c>,
/// <c>name = { version = "1.0", … }</c>, and a <c>version = "…"</c> line inside a
/// <c>[dependencies.name]</c> sub-table. A leading <c>=</c>/<c>^</c>/<c>~</c> operator
/// is preserved; a bare requirement stays bare (Cargo's idiomatic caret).
/// </remarks>
public static partial class CargoManifestPatcher
{
    /// <summary>Rewrites each bumped dependency's requirement (crate name → new version).</summary>
    public static ManifestPatch Apply(string content, IReadOnlyDictionary<string, string> bumps)
    {
        var canonical = bumps.ToDictionary(pair => pair.Key.Trim().ToLowerInvariant(), pair => pair.Value, StringComparer.Ordinal);
        var applied = new List<PackageBump>();

        var lines = content.ReplaceLineEndings("\n").Split('\n');
        var inDependenciesTable = false;
        string? subTableName = null;

        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = StripComment(lines[i]).Trim();
            if (trimmed.StartsWith('['))
            {
                inDependenciesTable = trimmed is "[dependencies]";
                subTableName = trimmed.StartsWith("[dependencies.", StringComparison.Ordinal) && trimmed.EndsWith(']')
                    ? trimmed["[dependencies.".Length..^1].Trim().ToLowerInvariant()
                    : null;
                continue;
            }

            if (subTableName is not null && canonical.TryGetValue(subTableName, out var subVersion))
            {
                TryRewriteVersionValue(lines, i, subTableName, subVersion, requireVersionKey: true, applied);
                continue;
            }

            if (!inDependenciesTable)
            {
                continue;
            }

            var equals = trimmed.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            var name = trimmed[..equals].Trim().ToLowerInvariant();
            if (canonical.TryGetValue(name, out var newVersion))
            {
                // Both plain (`name = "1.0"`) and inline-table (`name = { version = "1.0" … }`)
                // forms carry exactly one quoted requirement on the line.
                TryRewriteVersionValue(lines, i, name, newVersion, requireVersionKey: trimmed.Contains('{', StringComparison.Ordinal), applied);
            }
        }

        return new ManifestPatch(string.Join('\n', lines), applied);
    }

    // Rewrites the quoted value (after `version =` when required) on one line.
    private static void TryRewriteVersionValue(string[] lines, int index, string name, string newVersion, bool requireVersionKey, List<PackageBump> applied)
    {
        var line = lines[index];
        var match = requireVersionKey ? InlineVersionRegex().Match(line) : QuotedValueRegex().Match(line);
        if (!match.Success)
        {
            return;
        }

        var current = match.Groups["req"].Value;
        var replacement = KeepOperator(current, newVersion);
        if (string.Equals(current, replacement, StringComparison.Ordinal))
        {
            return;
        }

        applied.Add(new PackageBump(name, current, replacement));
        lines[index] = line[..match.Groups["req"].Index] + replacement + line[(match.Groups["req"].Index + match.Groups["req"].Length)..];
    }

    /// <summary>An explicit operator survives the bump; a bare requirement stays bare (caret).</summary>
    private static string KeepOperator(string currentReq, string newVersion) =>
        currentReq.Length > 0 && currentReq[0] is '=' or '^' or '~'
            ? $"{currentReq[0]}{newVersion}"
            : newVersion;

    private static string StripComment(string line)
    {
        var index = line.IndexOf('#', StringComparison.Ordinal);
        return index >= 0 ? line[..index] : line;
    }

    [GeneratedRegex(@"version\s*=\s*""(?<req>[^""]+)""")]
    private static partial Regex InlineVersionRegex();

    [GeneratedRegex(@"=\s*""(?<req>[^""]+)""")]
    private static partial Regex QuotedValueRegex();
}
