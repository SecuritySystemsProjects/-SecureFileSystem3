using System;

namespace FileSystem.Controllers
{
    public class CmdController
    {
        private models.FileSystem FileSystem;
        public CmdController(models.FileSystem fileSystem)
        {
            FileSystem = fileSystem;
        }

        public void HandleCommand(string cmd, FileSystem.models.FileSystem fs)
        {
            
                var args = cmd.Split(" ");
                var splitedArgs = new[] {"", "", "", "", "", "", ""};
                for (var i = 0; i < args.Length; i++)
                {
                    splitedArgs[i] = args[i];
                }
                switch (splitedArgs[0])
                {
                    case "ls":
                        FileSystem.Ls();
                        break;
                    case "pwd":
                        FileSystem.Pwd();
                        break;
                    case "cat":
                        FileSystem.Cat(splitedArgs[1]);
                        break;
                    case "cd":
                        FileSystem.Cd(splitedArgs[1]);
                        break;
                    case "rm":
                        FileSystem.Rm(splitedArgs[1]);
                        break;
                    case "mkdir":
                        FileSystem.MkDir(splitedArgs[1]);
                        break;
                    case "mkfile":
                        FileSystem.MkFile(splitedArgs[1], splitedArgs[2]);
                        break;
                    case "useradd":
                        FileSystem.UserAdd(splitedArgs[1], splitedArgs[2], splitedArgs[3], splitedArgs[4]);
                        break;
                    case "userdel":
                        FileSystem.UserDel(splitedArgs[1]);
                        break;
                    case "logout":
                        FileSystem.LogOut();
                        break;
                    default:
                        if (!fs.IsCodeChecking)
                        {
                            Console.WriteLine("Command not found");
                        }
                        else
                        {
                            Console.WriteLine("Enter code one more time:");
                        }
                        break;
                }
            
        }
    }
}