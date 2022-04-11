using System.Collections.Generic;

namespace FileSystem.models
{
    public class File {
        public string Name { get; set; }
        public string Content { get; set; }
        public List<AccessGroup> AccessList { get; set; }
    };
}