using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Net;

// create an ipscanner that enumerates an ip range (CIDR)
// function:
//      Scan(ipaddress) -> make connection -> true or false
//      IpListExtractor(CIDR) -> take a cidr in input and make a list of ip
//      Main(ipaddress/cidr) -> start scanner

namespace ipscanner
{
    class Program
    {
        private static bool Scan(string ipAddress)
        {
            // make a connection with ping command

            int timeout = 5;
            var connection = new Ping().Send(ipAddress, timeout);
            if (connection.Status == IPStatus.Success)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static List<string> IpListExtractor(string ipRange)
        {
            // take a range in input
            // extend that range as string array

            IPNetwork ipObject = IPNetwork.Parse(ipRange);
            List<string> ipArray = new List<string>();
            foreach (IPAddress ip in ipObject.ListIPAddress())
            {
                ipArray.Add(ip.ToString());
            }
            return ipArray;
        }

        static void Main(string[] args)
        {
            // use the first arguments as ipRange
            // extract a list of ipaddress
            // start a loop that iterate ipaddress array and print if is up
            // IMPROVE: add network features && add commandline arguments

            var ipRange = args[0];
            List<string> ipArray = IpListExtractor(ipRange);

            foreach (string ip in ipArray)
            {
                if (Scan(ip))
                {
                    Console.WriteLine("[+] {0} is UP", ip);
                }
            }

        }
    }
}