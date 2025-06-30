using System.Text.Json.Serialization;
using TaskNr2_2FA.Models;

public class Response<T>
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public T Data { get; set; }
    public ErrorDetails Error { get; set; }

    [JsonIgnore]
    public string Token { get; set; }

    public string AuthenticationStatus { get; set; }
}