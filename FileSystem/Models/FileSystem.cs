using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading;
using FileSystem.models.Security;

namespace FileSystem.models
{
    public class FileSystem
    {
        private Directory RootDir { get; set; }
        private Directory Directory { get; set; }
        public SecurityProvider SecurityProvider { get; set; }
        
        public string OsFile { get; set; }
        public Session Session { get; set; }
        public bool IsUserLoggedIn { get; private set; }
        public bool IsCodeChecking { get; private set; }
        
        public delegate void DirChanged (string name);
        public delegate void SendMessage (string name);
        public delegate void PrintFiles (List<File> files);
        public delegate void PrintDirectoryContent (List<File> files, List<Directory> directories);
        
        public event DirChanged OnDirChanged;
        public event DirChanged OnPrintDir;
        public event PrintDirectoryContent OnPrintDirectoryContent;
        public event DirChanged OnReadFile;
        public event DirChanged OnDirCreated;
        public event DirChanged OnFileCreated;
        public event DirChanged OnDeleteItem;
        public event SendMessage OnSendMessage;

        bool RightsGuard()
        {
            return true;
        }

        public void InitFromFile(string path)
        {
            var fileData = System.IO.File.ReadAllText(Path.GetFullPath(path));
            Directory = JsonSerializer.Deserialize<Directory>(fileData);
            NormalizeDirectories(Directory);
            RootDir = Directory;
            OsFile = path;
        }
        
        
        public void UseSecurity(Func<FileSystem, SecurityProvider> func)
        {
            SecurityProvider = func(this);
        }

        public void EnsureUserLoggedIn()
        {
            if (!IsUserLoggedIn)
            {
                var sCodeTimer = new Timer(_ => CheckSecretCode(IsUserLoggedIn), null, 0, 10000);
                while (!IsUserLoggedIn)
                {
                    var uCread = SecurityProvider.PasswordManager.GetUserCredentials();
                    var userInfo = SecurityProvider.ValidatePassword(uCread);
                    IsUserLoggedIn = userInfo is not null;
                    if (!IsUserLoggedIn)
                    {
                        Console.WriteLine("Incorrect login data! Try again!");
                        LogAction("EnsureUserLoggedIn", "info", $"Incorrect login data! Try again!");
                        continue;
                    };
                    
                    Session = new Session
                    {
                        User = new User {UserName = uCread.UserName, RightGroups = userInfo.RightGroups}
                    };
                    Console.WriteLine("Logged in as: " + uCread.UserName);
                    LogAction("EnsureUserLoggedIn", "info", $"Logged in as: " + uCread.UserName);
                }
            }
        }
        
        public void LogOut()
        {
            //LogAction("LogOut", "info", $"Run");
            Session = null;
            IsUserLoggedIn = false;
            Directory = RootDir;
            Console.WriteLine("Logout was successful!");
            //LogAction("LogOut", "info", $"Logout was successful!");
            EnsureUserLoggedIn();
        }

        public void CheckSecretCode(bool isActive)
        {
            if (isActive)
            {
                LogAction("CheckSecretCode", "info", $"Run CheckSecretCode");
                IsCodeChecking = true;
                var attemptCounter = 1;
                while (attemptCounter <= 3)
                {
                    var enteredCode = SecurityProvider.PasswordManager.GetUserSecretCode();
                    var isCodeValid = SecurityProvider.ValidateSecretCode(Session.User.UserName, enteredCode);
                    if (isCodeValid)
                    {
                        Console.WriteLine("Code validation successful");
                        LogAction("CheckSecretCode", "info", $"Code validation successful");

                        IsCodeChecking = false;
                        break;
                    }
                    if (attemptCounter != 3)
                    {
                        Console.WriteLine("Something went wrong! Try again!");
                        LogAction("CheckSecretCode", "warning", $"Something went wrong! Try again!");
                    }
                    attemptCounter++;
                }

                if (attemptCounter > 3)
                {
                    IsCodeChecking = false;
                    Console.WriteLine("You need to relogin in system!");
                    LogAction("CheckSecretCode", "alert", $"You need to relogin in system!");
                    LogOut();
                }
            }
        }

        public void Save()
        {
            System.IO.File.WriteAllText(OsFile,JsonSerializer.Serialize<Directory>(RootDir));
        }

        private void NormalizeDirectories(Directory dir)
        {
            foreach (var childDir in Directory.Directories)
            {
                childDir.UpDir = dir;
                if (childDir.Directories.Count > 0)
                {
                    NormalizeDirectories(childDir);
                }
            }
        }

        public File FindFile(string path)
        {
            if (!IsAbsolutePath(path)) return Directory.Files.Find(f => f.Name == path);
            var dir = RootDir;
            var pathParts = path.Split("/");
            if (pathParts.Length == 0) return null;
            pathParts = pathParts[1..];
            for (var i = 0; i < pathParts.Length; i++)
            {
                var part = pathParts[i];
                if (i == pathParts.Length - 1)
                {
                    return dir?.Files.Find(f => f.Name == part);
                }
                
                dir = dir?.Directories.Find(f => f.Name == part);
            }

            return null;
        }
        
        private bool IsAbsolutePath(string path)
        {
            return path.StartsWith("/");
        }

        public void Cd(string dirName)
        {
            LogAction("Cd", "info", $"Run with params: {dirName}");

            if (dirName == "")
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("Cd", "info", $"Incorrect params");
            }
            if (dirName == "..")
            {
                if (Directory.UpDir is null)
                {
                    OnDirChanged?.Invoke("Cannot back from root");
                    LogAction("Cd", "info", $"Cannot back from root");
                    return;
                }
                if (!SecurityProvider.AccessManager.HasRight(Directory.UpDir, "R"))
                {
                    OnDirCreated?.Invoke("You dont have rights to open this directory");
                    LogAction("Cd", "rightAlert", $"You dont have rights to open this directory");
                    return;
                }
                Directory = Directory.UpDir;
                OnDirChanged?.Invoke(Directory.Name);
                LogAction("Cd", "info", $"Directory changed to - " + Directory.Name);
            }
            else
            {
                var dir = Directory.Directories.Find(dir => dir.Name == dirName);
                if (dir is null)
                {
                    OnDirChanged?.Invoke("Directory not exists");
                    LogAction("Cd", "info", $"Directory not exists");
                }
                else
                {
                    if (SecurityProvider.AccessManager.HasRight(dir, "R"))
                    {
                        Directory = dir;
                        OnDirChanged?.Invoke(dir.Name);
                        LogAction("Cd", "info", $"Directory changed to - " + dir.Name);
                    }
                    else
                    {
                        OnDirChanged?.Invoke("You dont have rights to see directory");
                        LogAction("Cd", "rightAlert", $"You dont have rights to see directory");
                    }
                    
                }
            }
        }

        public void Pwd()
        {
            LogAction("Pwd", "info", $"Run");
            OnPrintDir?.Invoke(Directory.Name);
            LogAction("Pwd", "info", $"PWD res - {Directory.Name}");
        }
        public void Ls()
        {
            LogAction("Ls", "info", $"Run");
            OnPrintDirectoryContent?.Invoke(Directory.Files, Directory.Directories);
            LogAction("Ls", "info", $"LS res - {Directory.Files}, {Directory.Directories}");
        }

        public string Cat(string name)
        {
            LogAction("Cat", "info", $"Run with params: {name}");
            if (name == "")
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("Cat", "info", $"Incorrect params");
            }
            var file = FindFile(name);
            if (file is null)
            {
                OnReadFile?.Invoke("File not exist in this directory");
                LogAction("Cat", "info", $"File not exist in this directory");
                return null;
            }
            if (SecurityProvider.AccessManager.HasRight(file, "R"))
            {
                OnReadFile?.Invoke(file?.Content);
                LogAction("Cat", "info", $"{file?.Content}");
                return file?.Content;
            }

            OnReadFile?.Invoke("You dont have rights to see file");
            LogAction("Cat", "rightAlert", $"You dont have rights to see file");
            return null;
        }
        
        public void MkDir(string name)
        {
            LogAction("MkDir", "info", $"Run with params: {name}");
            if (name == "" )
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("MkDir", "info", $"Incorrect params");
            }
            var dir = Directory.Directories.Find(f => f.Name == name);
            
           
            var file = Directory.Files.Find(f => f.Name == name);
            if (file is not null || dir is not null)
            {
                OnDirCreated?.Invoke("Object with such name is already exist");
                LogAction("MkDir", "info", $"Object with such name is already exist");
            }
            else 
            {
                if (!SecurityProvider.AccessManager.HasRight(Directory, "C"))
                {
                    OnDirCreated?.Invoke("You dont have rights to create objects in this directory");
                    LogAction("MkDir", "rightAlert", $"You dont have rights to create objects in this directory");
                    return;
                }
                string[] userData = SecurityProvider.AccessManager.GetUserData();
                var AccessList = new List<AccessGroup> {};
                if (userData[0] == "admin")
                {
                    AccessList.Add(
                        new AccessGroup () {
                            GroupName = "admins", 
                            Rights = "RWCDN"
                        }
                    );
                }
                else
                {
                    foreach (var role in userData[1].Split('/'))
                    {
                        AccessList.Add(
                            new AccessGroup () {
                                GroupName = role, 
                                Rights = "RWD"
                            }
                        );
                    }
                }
                
                Directory.Directories.Add(new Directory
                {
                    Name = name,
                    UpDir = Directory,
                    AccessList = AccessList
                });
                OnDirCreated?.Invoke(name);
                LogAction("MkDir", "info", $"Dir created - {name}");
            }
        }
        
        public void MkFile(string name, string content = "")
        {
            LogAction("MkFile", "info", $"Run with params: {name}, {content}");
            if (name == "" )
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("MkFile", "info", $"Incorrect params");
            }
            var file = Directory.Files.Find(f => f.Name == name);
            var dir = Directory.Directories.Find(f => f.Name == name);
            if (dir is not null || file is not null)
            {
                OnFileCreated?.Invoke("Object with such name is already exist");
                LogAction("MkFile", "info", $"Object with such name is already exist");
            }
            else
            {
                if (!SecurityProvider.AccessManager.HasRight(Directory, "C"))
                {
                    OnDirCreated?.Invoke("You dont have rights to create objects in this directory");
                    LogAction("MkFile", "rightAlert", $"You dont have rights to create objects in this directory");
                    return;
                }

                string[] userData = SecurityProvider.AccessManager.GetUserData();

                var AccessList = new List<AccessGroup> {};
                
                if (userData[0] == "admin")
                {
                    AccessList.Add(
                        new () {
                            GroupName = "admins", 
                            Rights = "RWCDN"
                        }
                    );
                }
                else
                {
                    foreach (var role in userData[1].Split('/'))
                    {
                        AccessList.Add(
                            new AccessGroup () {
                                GroupName = role, 
                                Rights = "RWD"
                            }
                        );
                    }
                }
                
                Directory.Files.Add(new File
                {
                    Name = name,
                    Content = content,
                    AccessList = AccessList
                });
                OnFileCreated?.Invoke(name);
                LogAction("MkFile", "info", $"File created - {name}"); }
        }
        
        public void Rm(string name)
        {
            LogAction("Rm", "info", $"Run with params: {name}");
            if (name == "")
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("Rm", "warning", "Incorrect params");
            }
            var file = Directory.Files.Find(f => f.Name == name);
            var directory = Directory.Directories.Find(f => f.Name == name);
            if (file is not null)
            {
                if (!SecurityProvider.AccessManager.HasRight(file, "D"))
                {
                    OnDirCreated?.Invoke("You dont have rights to delete files in this directory");
                    LogAction("Rm", "rightAlert", "You dont have rights to delete files in this directory");
                    return;
                }
                Directory.Files.Remove(file);
                OnDeleteItem?.Invoke(name);
            }
            else if (directory is not null)
            {
                if (!SecurityProvider.AccessManager.HasRight(file, "D"))
                {
                    OnDirCreated?.Invoke("You dont have rights to delete directories in this directory");
                    LogAction("Rm", "rightAlert", "You dont have rights to delete files in this directory");
                    return;
                }
                Directory.Directories.Remove(directory);
                OnDeleteItem?.Invoke(name);
                LogAction("Rm", "info", $"Dir {name} was removed");
            }
            else
            {
                OnDeleteItem?.Invoke("File is not founded");
                LogAction("Rm", "info", $"File is not founded");
            }
        }

        public void UserAdd(string name, string password, string code, string roleGroups = "users")
        {
            LogAction("UserAdd", "info", $"Run with params: {name}, {roleGroups}");

            if (!SecurityProvider.AccessManager.IsAdmin())
            {
                OnSendMessage?.Invoke("Only admin can add users");
                LogAction("UserAdd", "rightAlert", "Only admin can add users");
            }
            if (name == "" || password == "" || code == "")
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("UserAdd", "warning", "Incorrect params");
            }
            if (name == "admin")
            {
                OnSendMessage?.Invoke("User name cant be 'admin'");
                LogAction("UserAdd", "info", "User name cant be 'admin'");
            }
            
            var pass = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
            var secretCode = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(code));
            var file = FindFile("/system/logbook.txt");
            file.Content = file.Content += $"\n{name}:{Convert.ToBase64String(pass)}:{Convert.ToBase64String(secretCode)}:{roleGroups}";
            Save();
            OnSendMessage?.Invoke("New user was added");
            LogAction("UserAdd", "info", "New user was added");

        }
        
        public void UserDel(string name)
        {
            LogAction("UserDel", "info", $"Run with params: {name}");
            if (!SecurityProvider.AccessManager.IsAdmin())
            {
                OnSendMessage?.Invoke("Only admin can add users");
                LogAction("UserDel", "rightAlert", "Only admin can add users");
            }

            if (name == "" )
            {
                OnSendMessage?.Invoke("Incorrect params");
                LogAction("UserDel", "warning", "Incorrect params");
            }
            var file = FindFile("/system/logbook.txt");
            file.Content = string.Join('\n',file.Content.Split("\n").Where(u => u.Split(":")[0] != name));
            Save();
            OnSendMessage?.Invoke("User was deleted");
            LogAction("UserDel", "info", "User was deleted");

        }
        
        private void LogAction(string actionName, string actionStatus, string result)
        {
            var file = FindFile("/system/logs.txt");
            file.Content = file.Content += $"\n{DateTime.Now}:{Session.User.UserName}:{actionName}:{actionStatus}:{result}";
            Save();
        }
    }
}