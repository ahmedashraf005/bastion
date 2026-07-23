FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src

COPY Bastion.Control.Api/Bastion.Control.Api.csproj Bastion.Control.Api/
COPY Bastion.Control.Domain/Bastion.Control.Domain.csproj Bastion.Control.Domain/
COPY dotnet-tools.json ./
RUN dotnet restore Bastion.Control.Api/Bastion.Control.Api.csproj
RUN dotnet tool restore

COPY . ./
RUN dotnet publish Bastion.Control.Api/Bastion.Control.Api.csproj \
    --configuration Release \
    --output /out \
    --no-restore
# EF constructs the context while generating the migration bundle. These
# values exist only at image-build time; Compose provides runtime settings.
ENV POSTGRES_DB=bastion \
    POSTGRES_USER=bastion \
    POSTGRES_PASSWORD=bastion_dev_password_change_me \
    POSTGRES_PORT=5432 \
    POSTGRES_HOST=postgres
RUN dotnet tool run dotnet-ef migrations bundle \
    --project Bastion.Control.Api/Bastion.Control.Api.csproj \
    --startup-project Bastion.Control.Api/Bastion.Control.Api.csproj \
    --configuration Release \
    --output /out/efbundle \
    --force

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /out ./
COPY docker-entrypoint.sh /usr/local/bin/bastion-control-entrypoint
RUN chmod +x /usr/local/bin/bastion-control-entrypoint

ENTRYPOINT ["/usr/local/bin/bastion-control-entrypoint"]
