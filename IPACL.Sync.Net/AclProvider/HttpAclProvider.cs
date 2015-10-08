using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace IPACL.Sync.Net.AclProvider
{
    class HttpAclProvider: IAclProvider
    {
        private WebClient _client;
        private string _url;

        public HttpAclProvider(String url)
        {
            _client = new WebClient();
            _url = url;
        }
        public List<IPAddress> GetWhitelisted()
        {
            byte[] data = _client.DownloadData(_url);
            String response = ASCIIEncoding.ASCII.GetString(data);
            List<IPAddress> ret = new List<IPAddress>();
            foreach (var ipStr in response.Split(new string[] {"\r\n", "\n"}, StringSplitOptions.RemoveEmptyEntries))
            {
                ret.Add(IPAddress.Parse(ipStr));
            }
            return ret;
        }
    }
}
