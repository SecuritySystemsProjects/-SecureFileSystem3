using System;

namespace FileSystem.Views
{
    public class ConsoleOutput
    {
        private models.FileSystem FileSystem;
        public ConsoleOutput(models.FileSystem fileSystem)
        {
            FileSystem = fileSystem;
        }

        public void SubscribeOnEvents()
        {
            FileSystem.OnPrintDir += name => Console.WriteLine("Curr dir is: " +name);
            FileSystem.OnDirChanged += name => Console.WriteLine("Dir changed to: " + name);
            FileSystem.OnReadFile += content => Console.WriteLine(content ?? "File not exists");
            FileSystem.OnDeleteItem += name => Console.WriteLine(name ?? "Not found item to delete");
            FileSystem.OnFileCreated += name => Console.WriteLine(name ?? "Can't create file.");
            FileSystem.OnDirCreated += name => Console.WriteLine(name ?? "Can't create directory.");
            FileSystem.OnPrintDirectoryContent += (files, directories) =>
            {
                if (files.Count > 0)
                {
                    Console.WriteLine("Files: ");
                    foreach (var file in files)
                    {
                        Console.WriteLine(file.Name);
                    }
                }

                if (directories.Count <= 0) return;
                Console.WriteLine("\nDirectories: ");
                foreach (var dir in directories)
                {
                    Console.WriteLine(dir.Name);
                }
            };
        }
    }
}