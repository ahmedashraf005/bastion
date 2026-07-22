using Bastion.Control.Api.Configuration;
using Bastion.Control.Api.Data;
using Bastion.Control.Api.Repositories;
using Microsoft.EntityFrameworkCore;

var settings = ControlSettings.FromRepositoryEnvironment();
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://localhost:{settings.Port}");

builder.Services.AddDbContext<BastionControlDbContext>(options =>
    options.UseNpgsql(settings.ConnectionString, npgsql =>
        npgsql.MigrationsHistoryTable("__control_ef_migrations", "public")));
builder.Services.AddScoped(_ => new CampaignReadRepository(settings.ConnectionString));
builder.Services.AddScoped(_ => new FindingReadRepository(settings.ConnectionString));
builder.Services.AddScoped(_ => new ProposedRuleReadRepository(settings.ConnectionString));
builder.Services.AddScoped(_ => new GateRequestReadRepository(settings.ConnectionString));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/campaigns", async (int? limit, CampaignReadRepository repository) =>
    Results.Ok(await repository.ListAsync(NormalizeLimit(limit))));
app.MapGet("/api/campaigns/{id:guid}", async (Guid id, CampaignReadRepository repository) =>
    await SingleOrNotFound(repository.GetAsync(id)));

app.MapGet("/api/findings", async (int? limit, FindingReadRepository repository) =>
    Results.Ok(await repository.ListAsync(NormalizeLimit(limit))));
app.MapGet("/api/findings/{id:guid}", async (Guid id, FindingReadRepository repository) =>
    await SingleOrNotFound(repository.GetAsync(id)));

var allowedProposalStatuses = new HashSet<string>(StringComparer.Ordinal)
{
    "pending_review", "approved", "rejected", "applied",
};
app.MapGet("/api/proposed-rules", async (string? status, int? limit, ProposedRuleReadRepository repository) =>
{
    if (status is not null && !allowedProposalStatuses.Contains(status))
    {
        return Results.BadRequest(new { error = "invalid proposed-rule status" });
    }

    return Results.Ok(await repository.ListAsync(status, NormalizeLimit(limit)));
});
app.MapGet("/api/proposed-rules/{id:guid}", async (Guid id, ProposedRuleReadRepository repository) =>
    await SingleOrNotFound(repository.GetAsync(id)));

app.MapGet("/api/gate-requests/recent", async (int? limit, GateRequestReadRepository repository) =>
    Results.Ok(await repository.ListRecentAsync(NormalizeLimit(limit))));

app.Run();

static int NormalizeLimit(int? requestedLimit) => Math.Clamp(requestedLimit ?? 50, 1, 100);

static async Task<IResult> SingleOrNotFound<T>(Task<T?> task) where T : class
{
    var value = await task;
    return value is null ? Results.NotFound() : Results.Ok(value);
}

public partial class Program;
