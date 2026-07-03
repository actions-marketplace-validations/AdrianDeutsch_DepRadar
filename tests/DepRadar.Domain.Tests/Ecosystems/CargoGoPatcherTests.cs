using DepRadar.Application.Ecosystems;
using Shouldly;
using Xunit;

namespace DepRadar.Domain.Tests.Ecosystems;

public sealed class CargoManifestPatcherTests
{
    private const string Manifest = """
        [package]
        name = "demo"
        version = "0.1.0"      # the crate's own version — must NOT be bumped

        [dependencies]
        regex = "=1.5.4"       # pinned
        serde = "1.0"          # bare = caret
        tokio = { version = "1.35", features = ["rt"] }

        [dependencies.smallvec]
        version = "~1.6.0"

        [dev-dependencies]
        regex = "=1.5.4"
        """;

    [Fact]
    public void Rewrites_all_three_forms_preserving_operators_and_ignoring_other_tables()
    {
        var patch = CargoManifestPatcher.Apply(Manifest, new Dictionary<string, string>
        {
            ["regex"] = "1.5.5",
            ["serde"] = "1.0.200",
            ["tokio"] = "1.38.0",
            ["smallvec"] = "1.6.1",
        });

        patch.Applied.Count.ShouldBe(4);
        patch.Content.ShouldContain("regex = \"=1.5.5\"");                       // '=' preserved
        patch.Content.ShouldContain("serde = \"1.0.200\"");                      // bare stays bare
        patch.Content.ShouldContain("tokio = { version = \"1.38.0\", features"); // inline table
        patch.Content.ShouldContain("version = \"~1.6.1\"");                     // sub-table, '~' preserved
        patch.Content.ShouldContain("version = \"0.1.0\"");                      // [package] untouched
        // dev-dependencies stay on the old pin.
        patch.Content.Split("regex = \"=1.5.4\"").Length.ShouldBe(2);
    }

    [Fact]
    public void Unknown_crate_applies_nothing()
    {
        CargoManifestPatcher.Apply(Manifest, new Dictionary<string, string> { ["unknown"] = "1.0.0" })
            .Applied.ShouldBeEmpty();
    }
}

public sealed class GoModPatcherTests
{
    private const string Manifest = """
        module example.com/demo

        go 1.22

        require github.com/gin-gonic/gin v1.9.0

        require (
            golang.org/x/text v0.3.7
            github.com/stretchr/testify v1.8.0 // indirect
        )
        """;

    [Fact]
    public void Rewrites_single_and_block_requires_with_v_prefix()
    {
        var patch = GoModPatcher.Apply(Manifest, new Dictionary<string, string>
        {
            ["github.com/gin-gonic/gin"] = "1.9.1",
            ["golang.org/x/text"] = "0.3.8",
        });

        patch.Applied.Count.ShouldBe(2);
        patch.Content.ShouldContain("require github.com/gin-gonic/gin v1.9.1");
        patch.Content.ShouldContain("golang.org/x/text v0.3.8");
        patch.Content.ShouldContain("github.com/stretchr/testify v1.8.0 // indirect"); // untouched
        // The module directive is not a requirement.
        patch.Content.ShouldContain("module example.com/demo");
    }

    [Fact]
    public void Identical_target_version_applies_nothing()
    {
        GoModPatcher.Apply(Manifest, new Dictionary<string, string> { ["golang.org/x/text"] = "0.3.7" })
            .Applied.ShouldBeEmpty();
    }
}
