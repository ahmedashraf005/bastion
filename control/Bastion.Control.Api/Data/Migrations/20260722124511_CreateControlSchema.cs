using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Bastion.Control.Api.Data.Migrations
{
    /// <inheritdoc />
    public partial class CreateControlSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "control");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP SCHEMA IF EXISTS control;");
        }
    }
}
