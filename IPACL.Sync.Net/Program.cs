using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SystemInteract;
using SystemInteract.Local;
using IPACL.Sync.Net.AclProvider;
using IPTables.Net;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Netfilter.TableSync;

namespace IPACL.Sync.Net
{
    class Program
    {
        private IAclProvider _aclProvider;
        private IpTablesSystem _system;

        public static bool Comparer(IpTablesRule rule1, IpTablesRule rule2)
        {
            var comment1 = rule1.GetModule<CommentModule>("comment");
            var comment2 = rule2.GetModule<CommentModule>("comment");

            if (comment1 == null || comment2 == null)
                return false;

            return comment1.CommentText == comment2.CommentText;
        }

        public Program(IAclProvider aclProvider)
        {
            _aclProvider = aclProvider;
            ISystemFactory system = new LocalFactory();
            _system = new IpTablesSystem(system, new IPTablesBinaryAdapter(), new IpSetBinaryAdapter(system));
        }

        public void PerformSync(string matches)
        {
            var whitelist = _aclProvider.GetWhitelisted();

            IpSetSet set = new IpSetSet(IpSetType.HashIp,"wl_ip",0, _system, IpSetSyncMode.SetAndEntries);
            foreach (var w in whitelist)
            {
                set.Entries.Add(new IpSetEntry(set, new IpCidr(w)));
            }
            
            IpSetSets sets = new IpSetSets(_system);
            sets.AddSet(set);
            sets.Sync();

            IpTablesRuleSet rules = new IpTablesRuleSet(4, _system);
            rules.AddRule("-A INPUT -m set --match-set wl_ip src -j ACCEPT -m comment --comment WLRULE");
            rules.AddRule("-A INPUT " + matches + " j DROP -m comment --comment DROPRULE");
            rules.Sync(new DefaultNetfilterSync<IpTablesRule>(Comparer));
        }

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("IPACL.Sync.Net [url] [match]");
            }
            else
            {
                Program p = new Program(new HttpAclProvider(args[0]));
                p.PerformSync(args[1]);
            }
        }
    }
}
