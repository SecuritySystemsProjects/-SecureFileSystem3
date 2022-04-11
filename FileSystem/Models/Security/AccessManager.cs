using System;
using System.Linq;

namespace FileSystem.models.Security
{
    public class AccessManager
    {
        public FileSystem FileSystem { get; set; }

        public bool HasRight(Directory dir, string right)
        {
            var userAccessGroups = FileSystem.Session.User.RightGroups.Split('/');
            var accessList = dir.AccessList.Where(group => Array.Exists(userAccessGroups, el => el == group.GroupName) );
            var directoryAccess = accessList.ToList().Find(group => group.Rights.ToList().Find(access => access == right.ToCharArray()[0]) != null);
            return directoryAccess != null;
        }
        
        public bool HasRight(File file, string right)
        {
            var userAccessGroups = FileSystem.Session.User.RightGroups.Split('/');
            var accessList = file.AccessList.Where(group => Array.Exists(userAccessGroups, el => el == group.GroupName) );
            var directoryAccess = accessList.ToList().Find(group => group.Rights.ToList().Find(access => access == right.ToCharArray()[0]) != null);
            return directoryAccess != null;
        }
        
        public string[] GetUserData()
        {
            string[] userData = {FileSystem.Session.User.UserName, FileSystem.Session.User.RightGroups};
            return userData;
        }

        public bool IsAdmin()
        {
            return FileSystem.Session.User.UserName == "admin";
        }
    }
}

/*
 R - открытие файлов для чтения;
 W - открытие файлов для записи; 
 C - создание файлов; 
 D - удаление файлов;
 N - переименование файлов и подкаталогов; 
 A - права админа;

 */