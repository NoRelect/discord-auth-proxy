using System.Text.Json.Serialization;

namespace DiscordAuthProxy;

public class DiscordPartialGuildResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = default!;

    [JsonPropertyName("name")]
    public string Name { get; set; } = default!;
}
