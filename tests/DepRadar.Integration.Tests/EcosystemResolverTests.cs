using System.Net;
using System.Text;
using DepRadar.Application;
using DepRadar.Application.Abstractions;
using DepRadar.Application.Risk;
using DepRadar.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Xunit;

namespace DepRadar.Integration.Tests;

/// <summary>
/// Drives the npm and PyPI scanners end-to-end against canned registry + OSV HTTP
/// responses — no network, no database. This pins down the transitive BFS resolution,
/// range/PEP 440 specifier matching, node de-duplication and OSV severity mapping
/// deterministically: the ecosystem cores that were previously only verified live.
/// </summary>
public sealed class EcosystemResolverTests
{
    [Fact]
    public async Task Npm_resolves_transitive_graph_dedups_and_maps_a_cve()
    {
        // express -> cookie, body-parser ; body-parser -> cookie (diamond on cookie).
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["/express"] = """{"dist-tags":{"latest":"4.18.2"},"versions":{"4.18.2":{"dependencies":{"cookie":"^0.5.0","body-parser":"^1.20.0"},"license":"MIT"}}}""",
            ["/body-parser"] = """{"dist-tags":{"latest":"1.20.1"},"versions":{"1.20.0":{"dependencies":{},"license":"MIT"},"1.20.1":{"dependencies":{"cookie":"^0.5.0"},"license":"MIT"}}}""",
            ["/cookie"] = """{"dist-tags":{"latest":"0.5.0"},"versions":{"0.5.0":{"dependencies":{},"license":"MIT"}}}""",
        });
        var osv = new OsvHandler(vulnerablePackage: "cookie");

        var assessment = await ScanAsync<INpmScanner>(
            ("NpmRegistryClient", registry),
            ("NpmVulnerabilitySource", osv),
            scanner => scanner.ScanAsync("express", null, TestContext.Current.CancellationToken));

        assessment.ShouldNotBeNull();
        // cookie is reached via two paths but appears once.
        assessment.Nodes.Select(n => n.Package.Value).OrderBy(x => x)
            .ShouldBe(["body-parser", "cookie", "express"]);
        // ^1.20.0 over {1.20.0, 1.20.1} resolves to the highest satisfying version.
        assessment.Nodes.Single(n => n.Package.Value == "body-parser").Version.ToString().ShouldBe("1.20.1");
        // express->cookie, express->body-parser, body-parser->cookie
        assessment.Edges.Count.ShouldBe(3);
        // the OSV advisory on cookie was mapped onto its node.
        assessment.Nodes.Single(n => n.Package.Value == "cookie").Input.Vulnerabilities.ShouldNotBeEmpty();
        assessment.Nodes.Single(n => n.Package.Value == "express").Input.Vulnerabilities.ShouldBeEmpty();
    }

    [Fact]
    public async Task PyPi_applies_pep440_specifiers_and_skips_extras()
    {
        // requests 2.19.1 -> urllib3 (>=1.21.1,<1.24), idna (>=2.5,<2.8); PySocks is extra-gated.
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["pypi/requests/json"] = """{"info":{"version":"2.31.0","requires_dist":null,"license":"Apache-2.0"},"releases":{"2.19.1":[],"2.31.0":[]}}""",
            ["pypi/requests/2.19.1/json"] = """{"info":{"version":"2.19.1","requires_dist":["urllib3 (>=1.21.1,<1.24)","idna (>=2.5,<2.8)","PySocks (>=1.5.6); extra == 'socks'"],"license":"Apache-2.0"},"releases":{"2.19.1":[],"2.31.0":[]}}""",
            ["pypi/urllib3/json"] = """{"info":{"version":"1.24","requires_dist":null,"license":"MIT"},"releases":{"1.22":[],"1.23":[],"1.24":[]}}""",
            ["pypi/urllib3/1.23/json"] = """{"info":{"version":"1.23","requires_dist":null,"license":"MIT"},"releases":{"1.22":[],"1.23":[],"1.24":[]}}""",
            ["pypi/idna/json"] = """{"info":{"version":"2.7","requires_dist":null,"license":"BSD"},"releases":{"2.7":[]}}""",
            ["pypi/idna/2.7/json"] = """{"info":{"version":"2.7","requires_dist":null,"license":"BSD"},"releases":{"2.7":[]}}""",
        });
        var osv = new OsvHandler(vulnerablePackage: "urllib3");

        var assessment = await ScanAsync<IPyPiScanner>(
            ("PyPiRegistryClient", registry),
            ("PyPiVulnerabilitySource", osv),
            scanner => scanner.ScanAsync("requests", "2.19.1", TestContext.Current.CancellationToken));

        assessment.ShouldNotBeNull();
        // PySocks (extra == 'socks') is not a runtime dependency and must be skipped.
        assessment.Nodes.Select(n => n.Package.Value).OrderBy(x => x)
            .ShouldBe(["idna", "requests", "urllib3"]);
        // "<1.24" excludes 1.24, so the compatible release is 1.23 (normalized to 1.23.0).
        assessment.Nodes.Single(n => n.Package.Value == "urllib3").Version.ToString().ShouldBe("1.23.0");
        assessment.Nodes.Single(n => n.Package.Value == "urllib3").Input.Vulnerabilities.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Npm_resolves_a_range_to_the_best_satisfying_version_and_misses_honestly()
    {
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["/express"] = """{"dist-tags":{"latest":"5.0.0"},"versions":{"4.18.2":{"dependencies":{},"license":"MIT"},"5.0.0":{"dependencies":{},"license":"MIT"}}}""",
        });

        var pinned = await ScanAsync<INpmScanner>(
            ("NpmRegistryClient", registry),
            ("NpmVulnerabilitySource", new OsvHandler(vulnerablePackage: "none")),
            scanner => scanner.ScanAsync("express", "^4.0.0", TestContext.Current.CancellationToken));

        // ^4.0.0 must NOT silently scan latest (5.0.0).
        pinned.ShouldNotBeNull();
        pinned.Nodes.Single().Version.ToString().ShouldBe("4.18.2");

        var unsatisfiable = await ScanAsync<INpmScanner>(
            ("NpmRegistryClient", registry),
            ("NpmVulnerabilitySource", new OsvHandler(vulnerablePackage: "none")),
            scanner => scanner.ScanAsync("express", "^9.0.0", TestContext.Current.CancellationToken));

        unsatisfiable.ShouldBeNull();
    }

    [Fact]
    public async Task PyPi_resolves_a_specifier_to_the_best_satisfying_release()
    {
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["pypi/requests/json"] = """{"info":{"version":"2.31.0","requires_dist":null,"license":"Apache-2.0"},"releases":{"2.19.1":[],"2.31.0":[]}}""",
            ["pypi/requests/2.19.1/json"] = """{"info":{"version":"2.19.1","requires_dist":null,"license":"Apache-2.0"},"releases":{"2.19.1":[],"2.31.0":[]}}""",
        });

        var assessment = await ScanAsync<IPyPiScanner>(
            ("PyPiRegistryClient", registry),
            ("PyPiVulnerabilitySource", new OsvHandler(vulnerablePackage: "none")),
            scanner => scanner.ScanAsync("requests", ">=2,<2.20", TestContext.Current.CancellationToken));

        assessment.ShouldNotBeNull();
        assessment.Nodes.Single().Version.ToString().ShouldBe("2.19.1");
    }

    [Fact]
    public async Task Fixed_version_is_the_smallest_patched_release_above_the_current_one()
    {
        // The advisory carries NuGet's canonical casing; the query uses the normalized id.
        var osv = new RouteHandler(new Dictionary<string, string>
        {
            ["v1/vulns/GHSA-test-0001"] = """
                {"id":"GHSA-test-0001","affected":[{"package":{"ecosystem":"NuGet","name":"Some.Package"},
                 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.0"},{"fixed":"2.0.0"}]}]}]}
                """,
        });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApplication();
        services.AddInfrastructure();
        services.AddHttpClient("OsvVulnerabilitySource").ConfigurePrimaryHttpMessageHandler(() => osv);
        StubExploitFeeds(services);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var source = scope.ServiceProvider.GetRequiredService<IVulnerabilitySource>();

        var fixedVersion = await source.GetFixedVersionAsync(
            "GHSA-test-0001",
            DepRadar.Domain.ValueObjects.PackageId.Create("some.package"),
            DepRadar.Domain.ValueObjects.SemVer.Parse("1.0.0"),
            TestContext.Current.CancellationToken);

        fixedVersion.ShouldBe("1.2.0");
    }

    /// <summary>Wires Application + Infrastructure, swaps the two named clients' handlers, runs the scanner.</summary>
    private static async Task<GraphAssessment?> ScanAsync<TScanner>(
        (string Name, HttpMessageHandler Handler) registry,
        (string Name, HttpMessageHandler Handler) vulnerabilities,
        Func<TScanner, Task<GraphAssessment?>> scan)
        where TScanner : notnull
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApplication();
        services.AddInfrastructure();
        services.AddHttpClient(registry.Name).ConfigurePrimaryHttpMessageHandler(() => registry.Handler);
        services.AddHttpClient(vulnerabilities.Name).ConfigurePrimaryHttpMessageHandler(() => vulnerabilities.Handler);
        StubExploitFeeds(services);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        return await scan(scope.ServiceProvider.GetRequiredService<TScanner>());
    }

    [Fact]
    public async Task Cargo_resolves_requirements_skips_dev_and_maps_yanked_to_deprecated()
    {
        // demo -> serde (^1.0), plus a dev-dependency and an optional one (both skipped).
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["api/v1/crates/demo/0.1.0/dependencies"] = """{"dependencies":[{"crate_id":"serde","req":"^1.0","kind":"normal","optional":false},{"crate_id":"criterion","req":"^0.5","kind":"dev","optional":false},{"crate_id":"tracing","req":"^0.1","kind":"normal","optional":true}]}""",
            ["api/v1/crates/serde/1.0.190/dependencies"] = """{"dependencies":[]}""",
            ["api/v1/crates/demo"] = """{"versions":[{"num":"0.1.0","yanked":false,"license":"MIT"}]}""",
            ["api/v1/crates/serde"] = """{"versions":[{"num":"1.0.190","yanked":false,"license":"MIT OR Apache-2.0"},{"num":"1.0.191","yanked":true,"license":"MIT OR Apache-2.0"}]}""",
        });

        var assessment = await ScanAsync<ICargoScanner>(
            ("CargoRegistryClient", registry),
            ("CargoVulnerabilitySource", new OsvHandler(vulnerablePackage: "serde")),
            scanner => scanner.ScanAsync("demo", "0.1.0", TestContext.Current.CancellationToken));

        assessment.ShouldNotBeNull();
        // dev + optional dependencies are skipped; ^1.0 must not select the yanked 1.0.191.
        assessment.Nodes.Select(n => n.Package.Value).OrderBy(x => x).ShouldBe(["demo", "serde"]);
        assessment.Nodes.Single(n => n.Package.Value == "serde").Version.ToString().ShouldBe("1.0.190");
        assessment.Nodes.Single(n => n.Package.Value == "serde").Input.Vulnerabilities.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Go_follows_exact_requires_and_escapes_upper_case_module_paths()
    {
        // demo -> golang.org/x/text v0.3.7 (+ an indirect require that must be skipped);
        // the root path contains an upper-case segment to pin the !-escaping.
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["github.com/!acme/demo/@latest"] = """{"Version":"v1.0.0"}""",
            ["github.com/!acme/demo/@v/v1.0.0.mod"] = "module github.com/Acme/demo\n\nrequire (\n\tgolang.org/x/text v0.3.7\n\tgithub.com/stretchr/testify v1.8.0 // indirect\n)\n",
            ["github.com/!acme/demo/@v/list"] = "v1.0.0\n",
            ["golang.org/x/text/@v/v0.3.7.mod"] = "module golang.org/x/text\n",
            ["golang.org/x/text/@v/list"] = "v0.3.7\nv0.3.8\n",
        });

        var assessment = await ScanAsync<IGoScanner>(
            ("GoProxyClient", registry),
            ("GoVulnerabilitySource", new OsvHandler(vulnerablePackage: "golang.org/x/text")),
            scanner => scanner.ScanAsync("github.com/Acme/demo", null, TestContext.Current.CancellationToken));

        assessment.ShouldNotBeNull();
        assessment.Nodes.Select(n => n.Package.Value).OrderBy(x => x)
            .ShouldBe(["github.com/Acme/demo", "golang.org/x/text"]);
        var text = assessment.Nodes.Single(n => n.Package.Value == "golang.org/x/text");
        text.Version.ToString().ShouldBe("0.3.7");           // exact require, no range resolution
        text.Input.Vulnerabilities.ShouldNotBeEmpty();       // OSV ecosystem=Go mapped
    }

    [Fact]
    public async Task Kev_and_epss_evidence_escalate_an_advisory_end_to_end()
    {
        // One package, one HIGH advisory with a CVE alias that is KEV-listed and has a 91% EPSS.
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["/left-pad"] = """{"dist-tags":{"latest":"1.3.0"},"versions":{"1.3.0":{"dependencies":{},"license":"MIT"}}}""",
        });
        var osv = new OsvHandler(vulnerablePackage: "left-pad");

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApplication();
        services.AddInfrastructure();
        services.AddHttpClient("NpmRegistryClient").ConfigurePrimaryHttpMessageHandler(() => registry);
        services.AddHttpClient("NpmVulnerabilitySource").ConfigurePrimaryHttpMessageHandler(() => osv);
        services.AddHttpClient("FirstEpssClient").ConfigurePrimaryHttpMessageHandler(
            () => new RouteHandler(new Dictionary<string, string>
            {
                ["data/v1/epss"] = """{"data":[{"cve":"CVE-2024-0001","epss":"0.91234"}]}""",
            }));
        services.AddHttpClient("CisaKevClient").ConfigurePrimaryHttpMessageHandler(
            () => new RouteHandler(new Dictionary<string, string>
            {
                ["known_exploited"] = """{"vulnerabilities":[{"cveID":"CVE-2024-0001"}]}""",
            }));

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var assessment = await scope.ServiceProvider.GetRequiredService<INpmScanner>()
            .ScanAsync("left-pad", null, TestContext.Current.CancellationToken);

        var vulnerability = assessment!.Nodes.Single().Input.Vulnerabilities.Single();
        vulnerability.Severity.ShouldBe(DepRadar.Domain.Risk.RiskLevel.Critical); // HIGH advisory + KEV ⇒ Critical
        vulnerability.Summary.ShouldContain("EPSS 91");
        vulnerability.Summary.ShouldContain("CISA KEV");
    }

    [Fact]
    public async Task Live_graph_query_serves_graph_and_risk_dtos_for_an_ecosystem()
    {
        var registry = new RouteHandler(new Dictionary<string, string>
        {
            ["/left-pad"] = """{"dist-tags":{"latest":"1.3.0"},"versions":{"1.3.0":{"dependencies":{},"license":"MIT"}}}""",
        });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApplication();
        services.AddInfrastructure();
        services.AddHttpClient("NpmRegistryClient").ConfigurePrimaryHttpMessageHandler(() => registry);
        services.AddHttpClient("NpmVulnerabilitySource").ConfigurePrimaryHttpMessageHandler(() => new OsvHandler(vulnerablePackage: "left-pad"));
        StubExploitFeeds(services);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var sender = scope.ServiceProvider.GetRequiredService<DepRadar.Application.Messaging.ISender>();

        var dto = await sender.Send(
            new DepRadar.Application.Live.GetLiveGraphQuery("npm", "left-pad", null),
            TestContext.Current.CancellationToken);

        dto.ShouldNotBeNull();
        dto.Ecosystem.ShouldBe("npm");
        dto.Graph.Nodes.Single().PackageId.ShouldBe("left-pad");
        dto.Graph.Nodes.Single().IsRoot.ShouldBeTrue();
        dto.Risk.Packages.Single().Findings.ShouldContain(f => f.Code == "VULN");
    }

    /// <summary>Keeps exploit-intelligence lookups off the network: empty EPSS + empty KEV catalog.</summary>
    private static void StubExploitFeeds(ServiceCollection services)
    {
        services.AddHttpClient("FirstEpssClient").ConfigurePrimaryHttpMessageHandler(
            () => new RouteHandler(new Dictionary<string, string> { ["data/v1/epss"] = """{"data":[]}""" }));
        services.AddHttpClient("CisaKevClient").ConfigurePrimaryHttpMessageHandler(
            () => new RouteHandler(new Dictionary<string, string> { ["known_exploited"] = """{"vulnerabilities":[]}""" }));
    }

    /// <summary>Serves a canned JSON body for the first route key contained in the request URL; 404 otherwise.</summary>
    private sealed class RouteHandler(IReadOnlyDictionary<string, string> routes) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            var match = routes.FirstOrDefault(route => url.Contains(route.Key, StringComparison.OrdinalIgnoreCase));
            var status = match.Value is null ? HttpStatusCode.NotFound : HttpStatusCode.OK;
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(match.Value ?? string.Empty, Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>OSV stub: returns one HIGH advisory iff the queried package name matches.</summary>
    private sealed class OsvHandler(string vulnerablePackage) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            var hit = body.Contains($"\"{vulnerablePackage}\"", StringComparison.Ordinal);
            var json = hit
                ? """{"vulns":[{"id":"GHSA-test-0001","summary":"Test advisory","aliases":["CVE-2024-0001"],"database_specific":{"severity":"HIGH"}}]}"""
                : """{"vulns":[]}""";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        }
    }
}
