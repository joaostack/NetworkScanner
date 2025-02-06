using Colorify;
using Colorify.UI;
using CsvHelper;
using CsvHelper.Configuration.Attributes;
using PacketDotNet;
using SharpPcap;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using ToolBox.Platform;

namespace NetworkScanner
{
    class Program
    {
        static readonly string ASCIIART = @"
__________      .__                    _________                
\______   \____ |__| __________   ____ \_   ___ \_____  ______  
 |     ___/  _ \|  |/  ___/  _ \ /    \/    \  \/\__  \ \____ \ 
 |    |  (  <_> )  |\___ (  <_> )   |  \     \____/ __ \|  |_> >
 |____|   \____/|__/____  >____/|___|  /\______  (____  /   __/ 
                        \/           \/        \/     \/|__|
By github.com/joaostack";
        public static Format _colorify { get; set; }
        static void Main(string[] args)
        {
            switch (OS.GetCurrent())
            {
                case "win":
                case "gnu":
                    _colorify = new Format(Theme.Dark);
                    break;
                case "mac":
                    _colorify = new Format(Theme.Light);
                    break;
            }

            Console.Clear();

            _colorify.WriteLine(ASCIIART, Colors.txtSuccess);

            // Interfaces menu
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                _colorify.WriteLine("No interface found!", Colors.txtDanger);
                return;
            }

            Console.WriteLine("\n" + new string('=', 50));
            for (int i = 0; i < devices.Count; i++)
            {
                var dev = devices[i];
                if (dev.MacAddress != null)
                {
                    var formatedMac = FormatMac(dev.MacAddress.ToString());
                    _colorify.WriteLine($"{i}: {dev.Description} | Mac: {formatedMac}", Colors.txtMuted);
                }
                else
                {
                    _colorify.WriteLine($"{i}: {dev.Description} | Mac: {dev.MacAddress}", Colors.txtMuted);
                }
            }
            Console.WriteLine(new string('=', 50) + "\n");

            _colorify.Write("Select an interface by entering the corresponding number: ", Colors.txtWarning);

            int selectedIndex;
            while (!int.TryParse(Console.ReadLine(), out selectedIndex) || selectedIndex < 0 || selectedIndex >= devices.Count)
            {
                _colorify.WriteLine("Invalid selection. Please enter a valid number.", Colors.txtDanger);
                _colorify.Write("Select an interface by entering the corresponding number: ", Colors.txtWarning);
            }

            var device = devices[selectedIndex];
            Console.WriteLine("Using: {0}", device.Description);
            device.Open(DeviceModes.Promiscuous);

            // Scan network devices
            var targets = ScanNetwork(device);
            foreach (var target in targets)
            {
                Console.WriteLine($"IP: {target.Item1} | MAC: {target.Item2}");
            }

            _colorify.ResetColor();
        }

        // scan network
        static List<Tuple<string, PhysicalAddress>> ScanNetwork(ILiveDevice device)
        {
            List<Tuple<string, PhysicalAddress>> devices = new List<Tuple<string, PhysicalAddress>>();

            _colorify.Write("Enter network IP (Ex: 192.168.0.0): ", Colors.txtWarning);
            var network = Console.ReadLine();

            string localIP = network;
            string baseIP = localIP.Substring(0, localIP.LastIndexOf('.') + 1);

            _colorify.WriteLine($"Base IP: {baseIP}", Colors.txtInfo);

            var attackerMac = device.MacAddress;
            var broadcastMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");

            _colorify.WriteLine($"Broadcast: {FormatMac(broadcastMac.ToString())}", Colors.txtInfo);
            _colorify.WriteLine("Scanning the network, please wait...", Colors.txtInfo);

            device.OnPacketArrival += Device_OnPacketArrival;
            device.StartCapture();

            var stopwatch = new Stopwatch();
            for (int i = 1; i < 255; i++)
            {
                var targetIpString = baseIP + i;
                var targetIp = IPAddress.Parse(targetIpString);
                var ethernetPacket = new EthernetPacket(attackerMac, broadcastMac, EthernetType.Arp);
                var arpPacket = new ArpPacket(
                    ArpOperation.Request,
                    broadcastMac,
                    targetIp,
                    attackerMac,
                    IPAddress.Parse(localIP)
                );

                ethernetPacket.PayloadPacket = arpPacket;
                device.SendPacket(ethernetPacket);

                // Wait for device to respond
                stopwatch.Restart();
                while (stopwatch.ElapsedMilliseconds < 300)
                {
                    // Wait
                }
            }
            stopwatch.Stop();

            return devices;
        }

        // Sniff ARP packets
        static HashSet<string> seenPackets = new HashSet<string>();
        static void Device_OnPacketArrival(object s, PacketCapture e)
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var arpPacket = packet.Extract<ArpPacket>();
            if (arpPacket != null)
            {
                var sourceIp = arpPacket.SenderProtocolAddress.ToString();
                var sourceMac = arpPacket.SenderHardwareAddress.ToString();
                var formatedSourceMac = FormatMac(sourceMac);
                var data = arpPacket.Operation;
                var key = $"{sourceIp} -> {sourceMac}";
                var vendor = GetVendor(FormatMac(sourceMac));

                if (!seenPackets.Contains(key))
                {
                    seenPackets.Add(key);
                    _colorify.WriteLine($"Device found: {sourceIp} -> {formatedSourceMac} : {vendor}", Colors.txtSuccess);
                }
            }
        }

        // Get vendor from MAC address
        static string GetVendor(string mac)
        {
            var macThree = GetMacThree(mac);
            using (var reader = new StreamReader("mac-vendors-export.csv"))
            {
                using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
                {
                    var records = csv.GetRecords<MacModel>().ToList();
                    var vendor = records.FirstOrDefault(record => record.MacPrefix.Equals(macThree, StringComparison.OrdinalIgnoreCase))?.VendorName;
                    return vendor ?? "Unknown";
                }
            }
        }

        // Get the first mac bytes
        static string GetMacThree(string mac)
        {
            var part = mac.Substring(0, 8);
            return part;
        }

        // Format MAC address to human readable format
        static string FormatMac(string mac)
        {
            if (!string.IsNullOrEmpty(mac))
            {
                return string.Join(":", Enumerable.Range(0, mac.Length / 2)
                                    .Select(i => mac.Substring(i * 2, 2)));
            }

            return mac;
        }

        public class MacModel
        {
            [Index(0)]
            public string MacPrefix { get; set; }
            [Index(1)]
            public string VendorName { get; set; }
            [Index(2)]
            public string Private { get; set; }
            [Index(3)]
            public string BlockType { get; set; }
            [Index(4)]
            public string LastUpdate { get; set; }
        }
    }
}