using System;
using System.Collections.Generic;

namespace CloudCherrySSO.Models
{
    public class SSOSubUser
    {
        public DateTime TimeStamp { get; set; } // UTC TimeStamp
        public string Userid { get; set; } // Unique User
        public string Email { get; set; } // Valid & Verified Email
        public string Role { get; set; } // Manager, MangerReadOnly
        public List<string> Locations { get; set; } // Optional
        public string SSOKey { get; set; }
        public string ManagedBy { get; set; }
    }
}