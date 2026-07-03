using DepRadar.Cli;

// CI-friendly entry point: dispatch the verb and return a process exit code.
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintUsage(Console.Out);
    return args.Length == 0 ? ExitCodes.Usage : ExitCodes.Ok;
}

// A dead registry/OSV after the resilience pipeline gave up is an OPERATIONAL failure,
// not a policy verdict — report it cleanly (no stack trace) with its own exit code so
// CI can retry instead of failing the gate.
try
{
    return args[0] switch
    {
        "scan" => await ScanCommand.RunAsync(args[1..], cts.Token),
        "diff" => await DiffCommand.RunAsync(args[1..], cts.Token),
        "fix" => await FixCommand.RunAsync(args[1..], cts.Token),
        "npm" => await NpmCommand.RunAsync(args[1..], cts.Token),
        "pypi" => await PyPiCommand.RunAsync(args[1..], cts.Token),
        "cargo" => await CargoCommand.RunAsync(args[1..], cts.Token),
        "go" => await GoCommand.RunAsync(args[1..], cts.Token),
        var unknown => Fail(unknown),
    };
}
catch (OperationCanceledException) when (cts.IsCancellationRequested)
{
    Console.Error.WriteLine("Cancelled.");
    return ExitCodes.Unavailable;
}
catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or TimeoutException)
{
    Console.Error.WriteLine($"error: an external service is unreachable — {exception.Message}");
    Console.Error.WriteLine("Check your network (or the registry/OSV status) and try again.");
    return ExitCodes.Unavailable;
}

static int Fail(string verb)
{
    Console.Error.WriteLine($"Unknown command '{verb}'.");
    PrintUsage(Console.Error);
    return ExitCodes.Usage;
}

static void PrintUsage(System.IO.TextWriter writer)
{
    writer.WriteLine(CliOptions.Usage);
    writer.WriteLine();
    writer.WriteLine(DiffCommand.Usage);
    writer.WriteLine(FixCommand.Usage);
    writer.WriteLine(NpmCommand.Usage);
    writer.WriteLine(PyPiCommand.Usage);
    writer.WriteLine(CargoCommand.Usage);
    writer.WriteLine(GoCommand.Usage);
}
