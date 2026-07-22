using DotNetEnv;
using Npgsql;

namespace Bastion.Control.Api.Configuration;

public sealed record ControlSettings(string ConnectionString, int Port)
{
    public static ControlSettings FromRepositoryEnvironment()
    {
        var environmentFile = FindRepositoryEnvironmentFile();
        if (environmentFile is not null)
        {
            Env.Load(environmentFile);
        }

        var database = Required("POSTGRES_DB");
        var user = Required("POSTGRES_USER");
        var password = Required("POSTGRES_PASSWORD");
        var port = int.Parse(Required("POSTGRES_PORT"));
        var controlPort = int.TryParse(Environment.GetEnvironmentVariable("CONTROL_PORT"), out var parsedPort)
            ? parsedPort
            : 5080;

        return new ControlSettings(BuildConnectionString(database, user, password, port), controlPort);
    }

    public static string BuildConnectionString(string database, string user, string password, int port) =>
        new NpgsqlConnectionStringBuilder
        {
            Host = "localhost",
            Port = port,
            Database = database,
            Username = user,
            Password = password,
        }.ConnectionString;

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"{name} is required in the repository .env file.");

    private static string? FindRepositoryEnvironmentFile()
    {
        for (var current = new DirectoryInfo(Directory.GetCurrentDirectory()); current is not null; current = current.Parent)
        {
            var candidate = Path.Combine(current.FullName, ".env");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
