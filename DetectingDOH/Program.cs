using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Text.RegularExpressions;


#pragma warning disable CA1416 // Validate platform compatibility
namespace DetectingDOH
{
    public class Thread2
    {
       // private static SHA256 Sha256 = SHA256.Create();
        private static MD5 md5 = MD5.Create();
        private static DateTime freshTime = DateTime.UtcNow;
        private static TimeSpan refreshTime = TimeSpan.FromHours(2);
        private static Dictionary<string, long> ImageSize = new Dictionary<string, long>();
        private static Dictionary<string, string> ImageMD5 = new Dictionary<string, string>();
        private static Dictionary<string, string> IP_domain = new Dictionary<string, string>();
        private static List<string> dnsMatches = new List<string>();
        private static List<string> singleNslookup = new List<string>();
        public static void DoWork()
        {
            var sw = Stopwatch.StartNew();
            //
            //while true..
            string queryId3 =
                "*[System[(EventID=3) and " +
                "TimeCreated[timediff(@SystemTime) <= 60000000]]]";
            //26400 with 30000000
            string queryDns =
                "*[System[(EventID=3008 or EventID=3009) and " +
                "TimeCreated[timediff(@SystemTime) <= 62000000]]]";
            string logName = "Microsoft-Windows-Sysmon/Operational";
            string dnslogName = "Microsoft-Windows-DNS-Client/Operational";
            EventLogQuery eventsQueryId3 = new EventLogQuery(logName,
                PathType.LogName, queryId3);
            EventLogQuery eventsQueryDns = new EventLogQuery(dnslogName,
                PathType.LogName, queryDns);
            EventLogReader logReaderId3 = new EventLogReader(eventsQueryId3);
            string tmpstr = GetDnsMatch(eventsQueryDns, "0.0.0.0");
            tmpstr = "";
            int eventCounter = 0;
            int pid = 0;
            string[] lines;
            string strImage = "";
            string strShortPath = "";
            string shortImage = "";
            string userName = "";
            string lastElementName = "";
            string destinationIp = "";
            string destinationPort = "";
            string nslookupArgs = "";
            string nslookupArgs2 = "";
            string nslookupArgs3 = "";
            int nslookupCount = 0;
            int tmpint;
            List<EventRecord> records = new List<EventRecord>();
            
            for (EventRecord er = logReaderId3.ReadEvent(); null != er; er = logReaderId3.ReadEvent())
            {
                records.Add(er);
                eventCounter++;
            }
            Console.WriteLine(eventCounter.ToString() + " Sysmon3 events");
            eventCounter = 0;

            var sw2 = Stopwatch.StartNew();
            for (int k = 0; k < records.Count; k++)
            {
                

                eventCounter++;
                strImage = "";
                destinationIp = "";
                destinationPort = "";
                nslookupArgs = "";
                nslookupArgs2 = "";
                nslookupArgs3 = "";
                tmpstr = records[k].ToXml();   // FormatDescription();
                //due to pain of working with sysmon xml, this parsing is best.  Fight me and my therapist.
                foreach (string data in tmpstr.Split("<"))
                {
                    if (data.StartsWith("Data Name='User'>"))
                    {
                        userName = "user" + data.Split("\\")[1].ToUpper().Replace(" ","_");
                        //Console.WriteLine("pid:" + pid); 
                    }

                    else if (data.StartsWith("Data Name='ProcessId'>"))
                    {
                        pid = Int32.Parse(data.Substring(22));
                        //Console.WriteLine("pid:" + pid); 
                    }
                    else if (data.StartsWith("Data Name='Image'>"))
                    {
                        
                        //Console.WriteLine(pid);
                        if (data == "Data Name='Image'>System" && pid == 4)
                        {
                            strImage = "c:\\Windows\\system32\\ntoskrnl.exe";
                            nslookupArgs3 = GetFileMD5(strImage) + "_";
                        }
                        else if (data.Contains("unknown process"))
                            strImage = "unknown_process";
                        else
                            strImage = data.Substring(18);
                        shortImage = strImage.Substring(strImage.LastIndexOf("\\") + 1);
                        Console.WriteLine(strImage);
                        shortImage = shortImage.Replace(".", "_");
                        //Console.WriteLine(strImage.Split("\\").Length);
                        if (strImage.Split("\\").Length > 1)
                            strShortPath = strImage.Split("\\")[0];
                        if (strImage.Split("\\").Length > 2)
                            strShortPath += "." + strImage.Split("\\")[1];
                        if (strImage.Split("\\").Length > 3)
                            strShortPath += "." + strImage.Split("\\")[2];
                        //strShortPath = strShortPath.Replace("\\", "-");
                        
                        strShortPath = strShortPath.Replace("(", "");
                        strShortPath = strShortPath.Replace(")", "");
                        strShortPath = strShortPath.Replace(":", "");
                        strShortPath = strShortPath.Replace(" ", "");
                        nslookupArgs += strShortPath + '.' + shortImage + ".";
                        nslookupArgs3 = GetFileMD5(strImage) + "_";
                        //Console.WriteLine(strShortPath);
                        
                        //Console.WriteLine("strImage:" + strImage);
                    }
                    
                    else if (data.StartsWith("Data Name='DestinationIp'>"))
                    {
                        
                        destinationIp = data.Substring(26);
                        //Console.WriteLine("looking for: " + destinationIp);
                        if (destinationIp != "0.0.0.0")
                        {
                            nslookupArgs = GetDnsMatch(eventsQueryDns, destinationIp) + nslookupArgs;
                            nslookupArgs2 = GetDnsMatch(eventsQueryDns, destinationIp)  + userName;
                            nslookupArgs2 += "." + destinationIp.Replace(".","_") + ".";
                            nslookupArgs3 = GetDnsMatch(eventsQueryDns, destinationIp) + nslookupArgs3;
                        }
                        else
                        {
                            nslookupArgs = "OKdns." + nslookupArgs;
                            nslookupArgs2 = "OKdns." + "0_0_0_0" + "." + userName;
                        }
                    }
                    else if (data.StartsWith("Data Name='DestinationPort'>"))
                    {
                        
                        destinationPort = data.Substring(28);
                        nslookupArgs += "dpt" + destinationPort;
                        nslookupArgs += " 192.168.2.153";
                        nslookupArgs2 += "dpt" + destinationPort;
                        nslookupArgs2 += " 192.168.2.153";
                        nslookupArgs3 += "dpt" + destinationPort;
                        nslookupArgs3 += " 192.168.2.153";
                        //Console.WriteLine(nslookupArgs);
                    }
                    
                    if (nslookupArgs.Contains(".dpt"))
                    {
                        
                        if (!nslookupArgs.Contains("nslookup"))
                        {
                            try
                            {
                                if (!singleNslookup.Contains(nslookupArgs)) //eventCounter % 5 == 0)
                                {
                                    nslookupCount++;
                                    //Console.WriteLine(nslookupArgs);
                                    singleNslookup.Add(nslookupArgs);
                                    //if (nslookupCount % 5 == 0)
                                    {
                                        //Console.WriteLine(nslookupArgs.Substring(0,nslookupArgs.IndexOf("192.168.2.153")));
                                        Console.WriteLine(nslookupArgs);
                                        Console.WriteLine(nslookupArgs2);
                                        Console.WriteLine(nslookupArgs3);
                                        //Console.WriteLine(strImage);
                                        Console.WriteLine("");
                                        //Console.Out.Flush();
                                    }
                                    
                                    Process p = new Process();
                                    p.StartInfo.FileName = "nslookup.exe";
                                    p.StartInfo.CreateNoWindow = true;
                                    p.StartInfo.Arguments = nslookupArgs;
                                    p.StartInfo.UseShellExecute = false;
                                    //p.Start();
                                    //Console.WriteLine(".");
                                    //Console.WriteLine(p.Id);
                                    //Console.WriteLine("-");
                                    //Thread.Sleep(300);
                                    p.Kill();
                                    //Console.Write(".");
                                    //output = p.StandardOutput.ReadToEnd();
                                    // nslookup example source
                                    // github.com/microsoft/WindowsProtocolTestSuites/
                                    // TestSuites/ADFamily/src/Adapter/MS-ADTS-PublishDC/HelperClass.cs
                                }
                            }
                            catch (System.InvalidOperationException exception)
                            {
                                Console.Write(""); //ok to ignore when call to kill has exception.
                            }
                            catch (System.ComponentModel.Win32Exception exception)
                            {
                                Console.Write("access denied"); //ok to ignore when call to kill has exception.
                            }
                        }

                    }

                }


            }
            sw.Stop();
            Console.WriteLine("");
            //Console.WriteLine(tmpstr);
            Console.WriteLine(sw.Elapsed.TotalSeconds);
            Console.WriteLine("DONE");
            //Console.ReadLine();
        }
        private static string GetDnsMatch(EventLogQuery eventsQueryDns, string destinationIp)
        {
            if (dnsMatches.Contains(destinationIp))
            {
                //Console.WriteLine("notDOH");
                return "OKdns."; // + destinationIp;
            }
            else if (destinationIp != "0.0.0.0")
            {
                //Console.WriteLine("**DOH**");
                return "DOHdns."; // + destinationIp;
            }

            /////if (IP_domain.ContainsKey(destinationIp)) ///fix so that domains with Duplicate in name are handled.
            /////    return "Duplicate_" + IP_domain[destinationIp];
            string[] lines;
            string strData;
            string result;
            int eventCounter = 0;
            EventLogReader logReaderDns = new EventLogReader(eventsQueryDns);
            if (dnsMatches == null || dnsMatches.Count < 1 || DateTime.UtcNow - freshTime > refreshTime)
            {
                eventCounter = 0;
                /////IP_domain = new Dictionary<string, string>();
                if (DateTime.UtcNow - freshTime > refreshTime)
                {
                    dnsMatches.Clear();
                }
                //Console.WriteLine("INFO: reading DNS events");
            }
            for (EventRecord er = logReaderDns.ReadEvent(); null != er; er = logReaderDns.ReadEvent())
            {
                eventCounter++;
                strData = er.ToXml();
                foreach (string data in strData.Split("<"))
                {
                    //if (data.StartsWith("Data Name='ProcessId'>"))
                    {
                        //Console.WriteLine(data);
                    }
                    if (data.StartsWith("Data Name='QueryResults'>"))
                    {
                        strData = data.Substring(25);
                        strData = strData.Replace("type:  5", "");
                        foreach (string tmp in strData.Split(";"))
                        {
                            if (Regex.Matches(tmp, @"[a-zA-Z]").Count == 0)
                            {
                                if (tmp.Length > 0)
                                {
                                    if (!dnsMatches.Contains(tmp))
                                        dnsMatches.Add(tmp);
                                }
                            }
                        }
                    }
                }
            }
            Console.WriteLine(eventCounter);
            return "initialized-GetDnsMatch";
        }
        private static string GetFileMD5(string image)
        {
            string hash;
            //if (DateTime.UtcNow - freshTime > refreshTime)
            //    ImageSha256 = new Dictionary<string, string>();
            if (ImageMD5.ContainsKey(image))
                return ImageMD5[image];
            else
            {
                if (File.Exists(image))
                {
                    using (FileStream stream = File.OpenRead(image))
                    {
                        byte[] checksum = md5.ComputeHash(stream);
                        hash = BitConverter.ToString(checksum).Replace("-",
                            String.Empty);
                        hash = hash.Substring(0, 6);
                        ImageMD5.Add(image, hash);
                        return hash;
                    }
                }
                else
                    return "noHash";
            }
        }

    }

    class Program
    {
        static void Main(string[] args)
        {
            Process p = Process.GetCurrentProcess();
            p.PriorityClass = ProcessPriorityClass.BelowNormal;
            Console.WriteLine("Priority is set to: " + p.PriorityClass);
            //Thread thread1 = new Thread(Thread1.SayHello);
            Thread thread2 = new Thread(Thread2.DoWork);
            //thread1.Start();
            thread2.Start();
            //Console.WriteLine("threads have started");
            //Console.ReadLine();
        }
    }
}

               
