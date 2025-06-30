using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TaskNr2_2FA.Migrations
{
    /// <inheritdoc />
    public partial class _2FALoginAttempCount : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FailedTwoFactorAttempts",
                table: "AspNetUsers",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastFailedTwoFactorAttempt",
                table: "AspNetUsers",
                type: "datetimeoffset",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FailedTwoFactorAttempts",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "LastFailedTwoFactorAttempt",
                table: "AspNetUsers");
        }
    }
}
