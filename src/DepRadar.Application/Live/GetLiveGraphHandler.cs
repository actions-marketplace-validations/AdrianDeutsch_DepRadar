using DepRadar.Application.Abstractions;
using DepRadar.Application.Analysis;
using DepRadar.Application.Graphs;
using DepRadar.Application.Messaging;
using DepRadar.Application.Risk;
using DepRadar.Domain.Risk;
using DepRadar.Domain.ValueObjects;

namespace DepRadar.Application.Live;

/// <summary>
/// Handles <see cref="GetLiveGraphQuery"/>: dispatches to the ecosystem's stateless
/// scanner and projects the one <see cref="GraphAssessment"/> into the SAME two DTOs
/// the persisted dashboard path serves — so the client renders both modes identically.
/// </summary>
public sealed class GetLiveGraphHandler(
    ProjectAnalyzer analyzer,
    INpmScanner npm,
    IPyPiScanner pypi,
    ICargoScanner cargo,
    IGoScanner go)
    : IRequestHandler<GetLiveGraphQuery, LiveGraphDto?>
{
    /// <inheritdoc />
    public async Task<LiveGraphDto?> Handle(GetLiveGraphQuery request, CancellationToken cancellationToken)
    {
        var ecosystem = request.Ecosystem.Trim().ToLowerInvariant();
        var assessment = ecosystem switch
        {
            "nuget" => await ScanNuGetAsync(request, cancellationToken),
            "npm" => await npm.ScanAsync(request.Package, request.Version, cancellationToken),
            "pypi" => await pypi.ScanAsync(request.Package, request.Version, cancellationToken),
            "cargo" => await cargo.ScanAsync(request.Package, request.Version, cancellationToken),
            "go" => await go.ScanAsync(request.Package, request.Version, cancellationToken),
            _ => throw new ArgumentException($"Unknown ecosystem '{request.Ecosystem}'.", nameof(request)),
        };

        return assessment is null
            ? null
            : new LiveGraphDto(ecosystem, ToGraphDto(assessment), ToRiskDto(assessment));
    }

    private async Task<GraphAssessment?> ScanNuGetAsync(GetLiveGraphQuery request, CancellationToken cancellationToken)
    {
        var pinned = request.Version is not null && SemVer.TryParse(request.Version, out var parsed) ? parsed : null;
        return await analyzer.AnalyzeAsync(PackageId.Create(request.Package), pinned, cancellationToken);
    }

    // The stateless assessment carries nodes + edge rows; project them into the same
    // shapes the DB-backed /graph and /graph/risk endpoints serve.
    private static PackageGraphDto ToGraphDto(GraphAssessment assessment)
    {
        var nodes = assessment.Nodes
            .Select(node => new GraphNodeDto(
                node.Package.Value,
                node.Version.ToString(),
                node.Package.Value == assessment.Root.Value))
            .ToList();

        var edges = assessment.Edges
            .Select(edge => new GraphEdgeDto(
                edge.DependentId,
                edge.DependentVersion,
                edge.DependencyId,
                edge.DependencyVersion,
                edge.VersionRange,
                edge.IsDirect,
                edge.Depth))
            .ToList();

        return new PackageGraphDto(assessment.Root.Original, assessment.Truncated, nodes, edges);
    }

    private static GraphRiskDto ToRiskDto(GraphAssessment assessment)
    {
        var scored = assessment.Nodes
            .OrderByDescending(node => node.Assessment.Score.Level)
            .ThenBy(node => node.Assessment.Score.Value)
            .ToList();

        var packages = scored
            .Select(node => PackageRiskDto.FromAssessment(node.Package, node.Version, node.Assessment))
            .ToList();

        var overallScore = scored.Count == 0 ? 100 : scored.Min(node => node.Assessment.Score.Value);
        var overallLevel = scored.Count == 0 ? RiskLevel.None : scored.Max(node => node.Assessment.Score.Level);

        return new GraphRiskDto(assessment.Root.Original, overallScore, overallLevel.ToString(), packages.Count, packages);
    }
}
