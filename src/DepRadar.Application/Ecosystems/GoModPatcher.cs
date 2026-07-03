using System.Text.RegularExpressions;
using DepRadar.Application.Projects;

namespace DepRadar.Application.Ecosystems;

/// <summary>
/// Applies version bumps to a <c>go.mod</c>'s text — the Go counterpart of
/// <see cref="ManifestPatcher"/>. A targeted line edit keeps formatting and comments
/// intact. Pure.
/// </summary>
/// <remarks>
/// Rewrites the version of matching <c>require</c> lines (single and block form).
/// Go requirements are exact and <c>v</c>-prefixed, so the bump is simply
/// <c>v{newVersion}</c>; <c>// indirect</c> entries never appear in the bumps (the
/// manifest parser skips them).
/// </remarks>
public static partial class GoModPatcher
{
    /// <summary>Rewrites each bumped module's version (module path → new version, without the v prefix).</summary>
    public static ManifestPatch Apply(string content, IReadOnlyDictionary<string, string> bumps)
    {
        var applied = new List<PackageBump>();

        var lines = content.ReplaceLineEndings("\n").Split('\n');
        var inRequireBlock = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].Trim();
            if (trimmed is "require (")
            {
                inRequireBlock = true;
                continue;
            }

            if (inRequireBlock && trimmed is ")")
            {
                inRequireBlock = false;
                continue;
            }

            var match = RequireLineRegex().Match(lines[i]);
            if (!match.Success)
            {
                continue;
            }

            var isRequirement = inRequireBlock || match.Groups["kw"].Success;
            if (!isRequirement || !bumps.TryGetValue(match.Groups["module"].Value, out var newVersion))
            {
                continue;
            }

            var current = match.Groups["version"].Value;
            var replacement = $"v{newVersion}";
            if (string.Equals(current, replacement, StringComparison.Ordinal))
            {
                continue;
            }

            applied.Add(new PackageBump(match.Groups["module"].Value, current, replacement));
            lines[i] = lines[i][..match.Groups["version"].Index] + replacement + lines[i][(match.Groups["version"].Index + match.Groups["version"].Length)..];
        }

        return new ManifestPatch(string.Join('\n', lines), applied);
    }

    // "require module v1.2.3" (kw group set) or a bare "module v1.2.3" block entry.
    [GeneratedRegex(@"^\s*(?:(?<kw>require)\s+)?(?<module>[A-Za-z0-9._~\-\/]+)\s+(?<version>v\S+)")]
    private static partial Regex RequireLineRegex();
}
