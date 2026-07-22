using Microsoft.EntityFrameworkCore;

namespace Bastion.Control.Api.Data;

public sealed class BastionControlDbContext(DbContextOptions<BastionControlDbContext> options)
    : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Control owns this schema, but v1 has no domain tables to map yet.
        modelBuilder.HasDefaultSchema("control");
    }
}
