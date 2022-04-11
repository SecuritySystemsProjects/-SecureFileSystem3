using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace FileSystem.models
{
    public class Directory
    {
        [JsonIgnore]
        public Directory UpDir { get; set; }
        [JsonInclude]
        public string Name { get; set; } 
        [JsonInclude]
        public List<AccessGroup> AccessList { get; set; }

        [JsonInclude] public List<Directory> Directories { get; set; } = new();
        [JsonInclude]
        public List<File> Files { get; set; } = new();
    }
}