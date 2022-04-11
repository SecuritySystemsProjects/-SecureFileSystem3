namespace FileSystem.models.Security
{
    public record UserCredentials
    {
        public string UserName { get; init; }
        public string Password { get; init; }
    };
}