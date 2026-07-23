using Bastion.Control.Api.Configuration;
using Npgsql;

namespace Bastion.Control.Tests;

public sealed class ControlSettingsTests
{
    [Fact]
    public void BuildConnectionString_uses_the_shared_postgres_values()
    {
        var connectionString = ControlSettings.BuildConnectionString(
            database: "bastion",
            user: "bastion",
            password: "dev-password",
            port: 5432);
        var builder = new NpgsqlConnectionStringBuilder(connectionString);

        Assert.Equal("localhost", builder.Host);
        Assert.Equal(5432, builder.Port);
        Assert.Equal("bastion", builder.Database);
        Assert.Equal("bastion", builder.Username);
        Assert.Equal("dev-password", builder.Password);
    }

    [Fact]
    public void BuildConnectionString_accepts_a_container_postgres_host()
    {
        var connectionString = ControlSettings.BuildConnectionString(
            database: "bastion",
            user: "bastion",
            password: "dev-password",
            port: 5432,
            host: "postgres");

        var builder = new NpgsqlConnectionStringBuilder(connectionString);

        Assert.Equal("postgres", builder.Host);
    }
}
