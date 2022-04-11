using System;
using System.Text.Json;
using FileSystem.Controllers;
using FileSystem.models;
using FileSystem.models.Security;
using FileSystem.Views;

namespace FileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            var fs = new models.FileSystem();
            fs.InitFromFile("./rk_os.json");
            fs.UseSecurity(fs=> new SecurityProvider(fs, new PasswordManager(), new AccessManager()));
            var consoleOutput = new ConsoleOutput(fs);
            var controller = new CmdController(fs);
            consoleOutput.SubscribeOnEvents();
            fs.EnsureUserLoggedIn();
            while (true)
            {
                controller.HandleCommand(Console.ReadLine(), fs);
            }
        }
    }
}