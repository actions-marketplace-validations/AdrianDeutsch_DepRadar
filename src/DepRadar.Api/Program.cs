using DepRadar.Api;
using DepRadar.Api.Endpoints;
using DepRadar.Api.Realtime;
using DepRadar.Application;
using DepRadar.Infrastructure;
using DepRadar.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Aspire service defaults: OpenTelemetry, health checks, service discovery, resilience.
builder.AddServiceDefaults();

// DbContext with the pgvector mapping enabled. The "depradardb" connection string
// is supplied by the AppHost via Aspire's service reference.
builder.Services.AddDepRadarDbContext(builder.Configuration.GetConnectionString("depradardb"));

// Redis L2 for HybridCache when orchestrated by Aspire; absent it falls back to L1.
if (!string.IsNullOrEmpty(builder.Configuration.GetConnectionString("cache")))
{
    builder.AddRedisDistributedCache("cache");
}

builder.Services.AddApplication();
builder.Services.AddInfrastructure(
    builder.Configuration["DepsDev:BaseUrl"],
    builder.Configuration["NuGet:BaseUrl"],
    builder.Configuration["Osv:BaseUrl"],
    builder.Configuration["Anthropic:ApiKey"],
    builder.Configuration["Anthropic:Model"],
    builder.Configuration["GitHub:Token"],
    builder.Configuration["Alerts:SlackWebhookUrl"],
    builder.Configuration["Alerts:GitHubRepo"]);

builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

// Optional edge hardening: per-client rate limiting (always on) + an opt-in API-key gate.
builder.Services.AddApiSecurity(builder.Configuration);

// SignalR for live scan progress; a background broadcaster bridges the worker's
// DB-written status to connected dashboard clients.
builder.Services.AddSignalR();
builder.Services.AddHostedService<ScanProgressBroadcaster>();

// Readiness: surface database connectivity on /health.
builder.Services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);

var app = builder.Build();

app.UseExceptionHandler();

// Rate limiting + optional API-key gate (no-ops when unconfigured).
app.UseApiSecurity();

// Serve the dashboard from wwwroot.
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapDefaultEndpoints();
app.MapOpenApi();

if (app.Environment.IsDevelopment())
{
    // Interactive API reference at /scalar/v1.
    app.MapScalarApiReference();

    // Apply EF Core migrations on startup (dev convenience).
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<DepRadarDbContext>();
    await dbContext.Database.MigrateAsync();
}

app.MapPackageEndpoints();
app.MapScanEndpoints();
app.MapProjectEndpoints();
app.MapDriftEndpoints();
app.MapLiveEndpoints();
app.MapHub<ScanHub>("/hubs/scan");

await app.RunAsync();
