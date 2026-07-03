namespace DepRadar.Cli;

/// <summary>
/// Process exit codes. CI gates on these: a non-zero code from <c>depradar scan</c>
/// fails the build.
/// </summary>
internal static class ExitCodes
{
    /// <summary>Analysis ran and the policy passed.</summary>
    public const int Ok = 0;

    /// <summary>Analysis ran but the policy was violated.</summary>
    public const int PolicyViolation = 1;

    /// <summary>Bad usage, or nothing could be resolved.</summary>
    public const int Usage = 2;

    /// <summary>
    /// An external service was unreachable (registry/OSV down, network cut) after the
    /// resilience pipeline gave up. Distinct from <see cref="PolicyViolation"/> so CI
    /// can retry instead of failing the gate.
    /// </summary>
    public const int Unavailable = 3;
}
