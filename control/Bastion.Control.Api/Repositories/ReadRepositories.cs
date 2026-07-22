using Bastion.Control.Domain;
using Dapper;
using Npgsql;

namespace Bastion.Control.Api.Repositories;

// These repositories deliberately contain SELECT-only, cross-schema SQL. Control
// does not map or migrate data owned by Gate or Strike.
public sealed class CampaignReadRepository(string connectionString)
{
    private NpgsqlConnection OpenConnection() => new(connectionString);

    public async Task<IReadOnlyList<CampaignSummary>> ListAsync(int limit)
    {
        const string sql = """
            SELECT id, objective, owasp_id AS OwaspId, target_key AS TargetKey, status,
                   started_at AS StartedAt, ended_at AS EndedAt, max_queries AS MaxQueries,
                   queries_used AS QueriesUsed, max_wall_clock_seconds AS MaxWallClockSeconds
            FROM strike.campaigns
            ORDER BY started_at DESC
            LIMIT @Limit;
            """;
        await using var connection = OpenConnection();
        var rows = await connection.QueryAsync<CampaignSummary>(sql, new { Limit = limit });
        return rows.AsList();
    }

    public async Task<CampaignSummary?> GetAsync(Guid id)
    {
        const string sql = """
            SELECT id, objective, owasp_id AS OwaspId, target_key AS TargetKey, status,
                   started_at AS StartedAt, ended_at AS EndedAt, max_queries AS MaxQueries,
                   queries_used AS QueriesUsed, max_wall_clock_seconds AS MaxWallClockSeconds
            FROM strike.campaigns
            WHERE id = @Id;
            """;
        await using var connection = OpenConnection();
        return await connection.QuerySingleOrDefaultAsync<CampaignSummary>(sql, new { Id = id });
    }
}

public sealed class FindingReadRepository(string connectionString)
{
    private NpgsqlConnection OpenConnection() => new(connectionString);

    public async Task<IReadOnlyList<FindingSummary>> ListAsync(int limit)
    {
        const string sql = """
            SELECT id, campaign_id AS CampaignId, owasp_id AS OwaspId,
                   matched_pattern AS MatchedPattern, gate_request_id AS GateRequestId,
                   promoted_strategy_id AS PromotedStrategyId, found_at AS FoundAt
            FROM strike.findings
            ORDER BY found_at DESC
            LIMIT @Limit;
            """;
        await using var connection = OpenConnection();
        var rows = await connection.QueryAsync<FindingSummary>(sql, new { Limit = limit });
        return rows.AsList();
    }

    public async Task<FindingSummary?> GetAsync(Guid id)
    {
        const string sql = """
            SELECT id, campaign_id AS CampaignId, owasp_id AS OwaspId,
                   matched_pattern AS MatchedPattern, gate_request_id AS GateRequestId,
                   promoted_strategy_id AS PromotedStrategyId, found_at AS FoundAt
            FROM strike.findings
            WHERE id = @Id;
            """;
        await using var connection = OpenConnection();
        return await connection.QuerySingleOrDefaultAsync<FindingSummary>(sql, new { Id = id });
    }
}

public sealed class ProposedRuleReadRepository(string connectionString)
{
    private NpgsqlConnection OpenConnection() => new(connectionString);

    public async Task<IReadOnlyList<ProposedRuleSummary>> ListAsync(string? status, int limit)
    {
        const string sql = """
            SELECT id, finding_id AS FindingId, proposed_id AS ProposedId,
                   proposed_pattern AS ProposedPattern, proposed_pattern_type AS ProposedPatternType,
                   proposed_normalize AS ProposedNormalize, proposed_description AS ProposedDescription,
                   verification_passed AS VerificationPassed, status, reviewer_note AS ReviewerNote,
                   reviewed_at AS ReviewedAt, applied_at AS AppliedAt, created_at AS CreatedAt
            FROM strike.proposed_rules
            WHERE @Status IS NULL OR status = @Status
            ORDER BY created_at DESC
            LIMIT @Limit;
            """;
        await using var connection = OpenConnection();
        var rows = await connection.QueryAsync<ProposedRuleSummary>(sql, new { Status = status, Limit = limit });
        return rows.AsList();
    }

    public async Task<ProposedRuleSummary?> GetAsync(Guid id)
    {
        const string sql = """
            SELECT id, finding_id AS FindingId, proposed_id AS ProposedId,
                   proposed_pattern AS ProposedPattern, proposed_pattern_type AS ProposedPatternType,
                   proposed_normalize AS ProposedNormalize, proposed_description AS ProposedDescription,
                   verification_passed AS VerificationPassed, status, reviewer_note AS ReviewerNote,
                   reviewed_at AS ReviewedAt, applied_at AS AppliedAt, created_at AS CreatedAt
            FROM strike.proposed_rules
            WHERE id = @Id;
            """;
        await using var connection = OpenConnection();
        return await connection.QuerySingleOrDefaultAsync<ProposedRuleSummary>(sql, new { Id = id });
    }
}

public sealed class GateRequestReadRepository(string connectionString)
{
    private NpgsqlConnection OpenConnection() => new(connectionString);

    public async Task<IReadOnlyList<GateRequestSummary>> ListRecentAsync(int limit)
    {
        const string sql = """
            SELECT id, received_at AS ReceivedAt, model, stream_requested AS StreamRequested,
                   upstream_status AS UpstreamStatus, policy_action AS PolicyAction, error
            FROM gate.requests
            ORDER BY received_at DESC
            LIMIT @Limit;
            """;
        await using var connection = OpenConnection();
        var rows = await connection.QueryAsync<GateRequestSummary>(sql, new { Limit = limit });
        return rows.AsList();
    }
}
