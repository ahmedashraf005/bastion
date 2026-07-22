using Bastion.Control.Api.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Bastion.Control.Api.Data;

public sealed class BastionControlDbContextFactory : IDesignTimeDbContextFactory<BastionControlDbContext>
{
    public BastionControlDbContext CreateDbContext(string[] args)
    {
        var settings = ControlSettings.FromRepositoryEnvironment();
        var options = new DbContextOptionsBuilder<BastionControlDbContext>()
            .UseNpgsql(settings.ConnectionString, npgsql =>
                npgsql.MigrationsHistoryTable("__control_ef_migrations", "public"))
            .Options;
        return new BastionControlDbContext(options);
    }
}
