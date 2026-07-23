using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Bastion.Control.Tests;

public sealed class ReadOnlyEndpointTests(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    [Fact]
    public async Task Campaign_attempts_returns_404_for_a_nonexistent_campaign()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/campaigns/00000000-0000-0000-0000-000000000000/attempts");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Stats_summary_returns_nonnegative_read_only_counts()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/stats/summary");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<StatsPayload>();

        Assert.NotNull(payload);
        Assert.True(payload.ActiveCampaigns >= 0);
        Assert.True(payload.ConfirmedBypasses >= 0);
        Assert.True(payload.RulesApplied >= 0);
        Assert.True(payload.RequestsBlocked24h >= 0);
    }

    [Fact]
    public async Task Dashboard_dev_origin_receives_the_explicit_cors_header()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Options, "/api/stats/summary");
        request.Headers.Add("Origin", "http://localhost:5173");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await client.SendAsync(request);

        response.EnsureSuccessStatusCode();
        Assert.Contains("http://localhost:5173", response.Headers.GetValues("Access-Control-Allow-Origin"));
    }

    private sealed class StatsPayload
    {
        public int ActiveCampaigns { get; init; }
        public int ConfirmedBypasses { get; init; }
        public int RulesApplied { get; init; }
        public int RequestsBlocked24h { get; init; }
    }
}
