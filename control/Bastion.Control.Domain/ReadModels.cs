namespace Bastion.Control.Domain;

public sealed class CampaignSummary
{
    public Guid Id { get; init; }
    public required string Objective { get; init; }
    public required string OwaspId { get; init; }
    public required string TargetKey { get; init; }
    public required string Status { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? EndedAt { get; init; }
    public int MaxQueries { get; init; }
    public int QueriesUsed { get; init; }
    public int MaxWallClockSeconds { get; init; }
}

public sealed class FindingSummary
{
    public Guid Id { get; init; }
    public Guid CampaignId { get; init; }
    public required string OwaspId { get; init; }
    public required string MatchedPattern { get; init; }
    public Guid? GateRequestId { get; init; }
    public string? PromotedStrategyId { get; init; }
    public DateTimeOffset FoundAt { get; init; }
}

public sealed class ProposedRuleSummary
{
    public Guid Id { get; init; }
    public Guid FindingId { get; init; }
    public required string ProposedId { get; init; }
    public required string ProposedPattern { get; init; }
    public required string ProposedPatternType { get; init; }
    public required string ProposedNormalize { get; init; }
    public required string ProposedDescription { get; init; }
    public bool VerificationPassed { get; init; }
    public required string Status { get; init; }
    public string? ReviewerNote { get; init; }
    public DateTimeOffset? ReviewedAt { get; init; }
    public DateTimeOffset? AppliedAt { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class GateRequestSummary
{
    public Guid Id { get; init; }
    public DateTimeOffset ReceivedAt { get; init; }
    public required string Model { get; init; }
    public bool StreamRequested { get; init; }
    public int? UpstreamStatus { get; init; }
    public string? PolicyAction { get; init; }
    public string? Error { get; init; }
}

public sealed class AttemptSummary
{
    public Guid Id { get; init; }
    public int SequenceNumber { get; init; }
    public required string Source { get; init; }
    public int RoundNumber { get; init; }
    public bool Matched { get; init; }
    public bool Pruned { get; init; }
    public int? TargetStatus { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class StatsSummary
{
    public int ActiveCampaigns { get; init; }
    public int ConfirmedBypasses { get; init; }
    public int RulesApplied { get; init; }
    public int RequestsBlocked24h { get; init; }
}
