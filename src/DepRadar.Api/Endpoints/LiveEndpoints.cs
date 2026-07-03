using DepRadar.Application.Live;
using DepRadar.Application.Messaging;

namespace DepRadar.Api.Endpoints;

/// <summary>
/// The live multi-ecosystem scan: resolves and scores in-process (no queue, no
/// database), so the dashboard can render npm/PyPI/Cargo/Go graphs without the
/// NuGet-only persistence pipeline.
/// </summary>
internal static class LiveEndpoints
{
    private static readonly string[] Ecosystems = ["nuget", "npm", "pypi", "cargo", "go"];

    /// <summary>Registers the <c>/api/live</c> endpoint group.</summary>
    public static IEndpointRouteBuilder MapLiveEndpoints(this IEndpointRouteBuilder app)
    {
        // Catch-all package segment: Go module paths and npm scopes contain slashes.
        app.MapGet("/api/live/{ecosystem}/{**package}", GetLiveGraphAsync)
            .WithTags("Live")
            .WithName("GetLiveGraph")
            .WithSummary("Resolve and score a package of any supported ecosystem in-process (graph + risk ranking).")
            .Produces<LiveGraphDto>()
            .Produces(StatusCodes.Status404NotFound);

        return app;
    }

    private static async Task<IResult> GetLiveGraphAsync(
        string ecosystem,
        string package,
        string? version,
        ISender sender,
        CancellationToken cancellationToken)
    {
        if (!Ecosystems.Contains(ecosystem.Trim().ToLowerInvariant()))
        {
            return Results.BadRequest(new { error = $"Unknown ecosystem '{ecosystem}'. Expected one of: {string.Join(", ", Ecosystems)}." });
        }

        var result = await sender.Send(new GetLiveGraphQuery(ecosystem, package, version), cancellationToken);
        return result is null
            ? Results.NotFound(new { error = $"'{package}' could not be resolved on {ecosystem}." })
            : Results.Ok(result);
    }
}
