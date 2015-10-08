using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IPACL.Sync.Net.AclProvider
{
    interface IAclProvider
    {
        List<IPAddress> GetWhitelisted();
    }
}
