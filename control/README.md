# Bastion.Control

Bastion.Control is the ASP.NET control-plane service for Bastion.

## .NET SDK convention

Run every .NET command in this directory through the project-local wrapper:

```sh
./dotnet10 run --project Bastion.Control.Api
./dotnet10 test
./dotnet10 ef migrations add <name> --project Bastion.Control.Api
```

Do **not** use bare `dotnet` here. On this machine it resolves to a
pre-existing .NET 8 installation unrelated to this project. `./dotnet10`
uses the installed .NET 10 host, while `global.json` records the required
SDK version for contributors and CI.
