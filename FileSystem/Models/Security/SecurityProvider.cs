namespace FileSystem.models.Security
{
    public class SecurityProvider
    {
        private FileSystem FileSystem { get; }
        public PasswordManager PasswordManager { get; }
        public AccessManager AccessManager { get; }
        
        public SecurityProvider(FileSystem fs, PasswordManager passwordManager, AccessManager accessManager)
        {
            FileSystem = fs;
            PasswordManager = passwordManager;
            AccessManager = accessManager;
            PasswordManager.FileSystem = fs;
            AccessManager.FileSystem = fs;
        }

        public User ValidatePassword(UserCredentials credentials)
        {
            return PasswordManager.ValidatePassword(credentials);
        }
        
        public bool ValidateSecretCode(string username, string secretCode)
        {
            return PasswordManager.ValidateSecretCode(username, secretCode);
        }


    }
}