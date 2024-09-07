FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["DiscordAuthProxy/DiscordAuthProxy.csproj", "DiscordAuthProxy/"]
RUN dotnet restore "DiscordAuthProxy/DiscordAuthProxy.csproj"
COPY . .
WORKDIR "/src/DiscordAuthProxy"
RUN dotnet build "DiscordAuthProxy.csproj" -c Release -o /app/build
RUN dotnet test "DiscordAuthProxy.csproj"

FROM build AS publish
RUN dotnet publish "DiscordAuthProxy.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
USER $APP_UID
CMD ["dotnet", "DiscordAuthProxy.dll"]