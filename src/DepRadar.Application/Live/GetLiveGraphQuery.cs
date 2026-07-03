using DepRadar.Application.Graphs;
using DepRadar.Application.Messaging;
using DepRadar.Application.Risk;

namespace DepRadar.Application.Live;

/// <summary>
/// Query: resolve and score a package of ANY supported ecosystem in-process (no queue,
/// no database) — the dashboard's live multi-ecosystem mode. Returns
/// <see langword="null"/> when the package cannot be resolved on its registry.
/// </summary>
/// <param name="Ecosystem">One of <c>nuget</c>, <c>npm</c>, <c>pypi</c>, <c>cargo</c>, <c>go</c>.</param>
/// <param name="Package">The package/module/crate name.</param>
/// <param name="Version">Optional exact version or ecosystem range/specifier; null = latest.</param>
public sealed record GetLiveGraphQuery(string Ecosystem, string Package, string? Version) : IRequest<LiveGraphDto?>;

/// <summary>The live scan result: the graph shape plus the rolled-up risk view.</summary>
public sealed record LiveGraphDto(string Ecosystem, PackageGraphDto Graph, GraphRiskDto Risk);
