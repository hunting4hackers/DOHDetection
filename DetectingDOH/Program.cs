using System;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics.Eventing.Reader;
namespace DetectingDOH
{
    public class Thread1
    {
        private static DateTime freshTime = DateTime.UtcNow;
        private static TimeSpan refreshTime = TimeSpan.FromHours(2);
        private static Dictionary<string, string> IP_domain = new Dictionary<string, string>();
        private static List<string> dnsMatches = new List<string>();
        public static void DoWork()
        {
            string queryId3 =
                "*[System[(EventID=3) and " +
                "TimeCreated[timediff(@SystemTime) <= 30000]]]";
            string queryId22 =
                "*[System[(EventID=3008 or EventID=3009) and " +
                "TimeCreated[timediff(@SystemTime) <= 31000]]]";
            string logName = "Microsoft-Windows-Sysmon/Operational";
            string dnslogName = "Microsoft-Windows-DNS-Client/Operational";
            EventLogQuery eventsQueryId3 = new EventLogQuery(logName,
                PathType.LogName, queryId3);
            EventLogQuery eventsQueryId22 = new EventLogQuery(dnslogName,
                PathType.LogName, queryId22);
            EventLogReader logReaderId3 = new EventLogReader(eventsQueryId3);
            int eventCounter = 0;
            int pid = 0;
            string[] lines;
            string strImage = "";
            string shortImage = "";
            string tmpstr = "";
            string destinationIp = "";
            List<EventRecord> records = new List<EventRecord>();
            //source..// github.com/angularadam/FastEvents
            for (EventRecord er = logReaderId3.ReadEvent(); null != er; er = logReaderId3.ReadEvent())
            {
                eventCounter++;
                records.Add(er);
            }
            foreach (EventRecord ev in records)
            {
                Console.WriteLine("");
                strImage = "";
                destinationIp = "";
                tmpstr = ev.FormatDescription().Replace("\"", "");
                lines = tmpstr.Split(new[] {
                    Environment.NewLine }, StringSplitOptions.None);
                foreach (string line in lines)
                {
                    if (line.StartsWith("ProcessId:"))
                    {
                        pid = Int32.Parse(line.Replace("ProcessId: ", ""));
                        if (pid == 4)
                            strImage = "c:\\Windows\\system32\\ntoskrnl.exe";
                    }
                    else if (line.StartsWith("Image:"))
                    {
                        if (line.Contains("\\"))
                        {
                            strImage = line.Replace("Image: ", "");
                            shortImage = strImage.Substring(strImage.LastIndexOf("\\") + 1);
                            shortImage = shortImage.Replace(".", "_");
                            Console.Write(shortImage + "_");
                        }
                        else if (strImage == "c:\\Windows\\system32\\ntoskrnl.exe")
                        {
                            shortImage = "ntoskrnl_exe";
                            Console.Write(shortImage + "_");
                        }
                    }
                    else if (line.StartsWith("DestinationIp:"))
                    {
                        destinationIp = line.Replace("DestinationIp: ", "");
                        Console.Write(GetDnsMatch(eventsQueryId22, destinationIp));
                    }
                }
            }
        }
        private static string GetDnsMatch(EventLogQuery eventsQueryId22, string destinationIp)
        {
            string[] lines;
            string strData;
            string result;
            if (dnsMatches == null || dnsMatches.Count < 1 || DateTime.UtcNow - freshTime > refreshTime)
            {
                IP_domain = new Dictionary<string, string>();
                if (DateTime.UtcNow - freshTime > refreshTime)
                {
                    dnsMatches.Clear();
                }
                EventLogReader logReaderId22 = new EventLogReader(eventsQueryId22);
                for (EventRecord er = logReaderId22.ReadEvent(); null != er; er = logReaderId22.ReadEvent())
                {
                    strData = "";
                    lines = er.FormatDescription().Split(new[] {
                        Environment.NewLine }, StringSplitOptions.None);
                    foreach (string line in lines)
                    {
                        strData = line.Replace("DNS query is completed for the name ", "");
                        strData = strData.Replace("Network query initiated for the name ", "");
                    }
                    if (strData.Length > 0)
                        dnsMatches.Add(strData);
                }
            }
            if (IP_domain.ContainsKey(destinationIp))
                return "NotDOH_" + IP_domain[destinationIp];
            else
            {
                foreach (string dnsMatch in dnsMatches)
                {
                    if (dnsMatch.Contains(destinationIp))
                    {
                        result = dnsMatch.Substring(0, dnsMatch.IndexOf(" "));
                        result = result.Replace(",", "");
                        IP_domain.Add(destinationIp, result);
                        return "NotDOH_" + result;
                    }
                }
            }
            return "IsDOH_" + destinationIp;
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            //Process p = Process.GetCurrentProcess();
            //p.PriorityClass = ProcessPriorityClass.BelowNormal;
            //Console.WriteLine("Priority is set to: " + p.PriorityClass);
            Thread thread1 = new Thread(Thread1.DoWork);
            thread1.Start();
            //Console.WriteLine("threads have started");
            //Console.ReadLine();
        }
    }
}
