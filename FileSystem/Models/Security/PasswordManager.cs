using System;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace FileSystem.models.Security
{
    public class PasswordManager
    {
        public FileSystem FileSystem { get; set; }
        public UserCredentials GetUserCredentials()
        {
            var userName = "";
            var userPassword = "";
            Console.WriteLine("username: ");
            while (userName?.Length == 0)
            {
                userName = Console.ReadLine();
            }

            Console.WriteLine("password: ");
            while (userPassword.Length == 0)
            {
                userPassword = ReadPassword();
            }

            return new UserCredentials {UserName = userName, Password = userPassword};
        }
        public string GetUserSecretCode()
        {
            var userCode = ""; 
            Console.WriteLine("Enter secret code: ");
            while (userCode?.Length == 0)
            {
                userCode = Console.ReadLine();
            }

            return userCode;
        }
        
        private string ReadPassword()
        {
            ConsoleKeyInfo key;
            string code = "";
            do
            {
                key = Console.ReadKey(true);

                if (Char.IsNumber(key.KeyChar))
                {
                    Console.Write("*");
                }
                code += key.KeyChar;
            } while (key.Key != ConsoleKey.Enter);

            return code.Trim();

        }

        private string GetPasswordHash(string pass)
        {
            var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
            return Convert.ToBase64String(hash);
        }

        public User ValidatePassword(UserCredentials credentials)
        {
            var passFile = FileSystem.FindFile("/system/logbook.txt")?.Content;
            if (passFile is null) return null;
            foreach (var userRow in passFile.Split("\n"))
            {
                var userData = userRow.Split(":");
                if (userData[0] != credentials.UserName) continue;
                var isLoggedInSuccess = GetPasswordHash(credentials.Password.Trim()) == userData[1];

                if (isLoggedInSuccess)
                {
                    return new User {UserName = userData[0], RightGroups = userData[3]};
                }
                else return null;
            }
            return null;
        }
        
        public bool ValidateSecretCode(string userName, string secretCode)
        {
            var passFile = FileSystem.FindFile("/system/logbook.txt")?.Content;
            if (passFile is null) return false;
            foreach (var userRow in passFile.Split("\n"))
            {
                var userData = userRow.Split(":");
                if (userData[0] != userName) continue;
                return GetPasswordHash(secretCode.Trim()) == userData[2];
            }
            return false;
        }
    }
}