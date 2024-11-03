using Colorify;
using Colorify.UI;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
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
                        \/           \/        \/     \/|__|";
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

            _colorify.WriteLine(ASCIIART, Colors.txtSuccess);

            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No iface found!");
                return;
            }

            Console.WriteLine("\n" + new string('=', 50));
            for (int i = 0; i < devices.Count; i++)
            {
                var dev = devices[i];
                _colorify.WriteLine($"{i}: Name: {dev.Name} | Desc: {dev.Description} | Mac: {dev.MacAddress}", Colors.txtPrimary);
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
            Console.WriteLine("Using: {0}", device.Name);
            device.Open(DeviceModes.Promiscuous);

            var targets = ScanNetwork(device);
            foreach (var target in targets)
            {
                Console.WriteLine($"IP: {target.Item1} | MAC: {target.Item2}");
            }


            _colorify.ResetColor();
        }

        static List<Tuple<string, PhysicalAddress>> ScanNetwork(ILiveDevice device)
        {
            List<Tuple<string, PhysicalAddress>> devices = new List<Tuple<string, PhysicalAddress>>();
            string localIP = "192.168.0.0"; // NETWORK HERE!!!
            string baseIP = localIP.Substring(0, localIP.LastIndexOf('.') + 1);
            var attackerMac = device.MacAddress;
            var broadcastMac = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");

            _colorify.WriteLine("Scanning the network, please wait...", Colors.txtInfo);

            device.OnPacketArrival += Device_OnPacketArrival;
            device.StartCapture();

            for (int i = 1; i < 255; i++)
            {
                string targetIpString = baseIP + i;
                var targetIp = IPAddress.Parse(targetIpString);
                var ethernetPacket = new EthernetPacket(attackerMac, broadcastMac, EthernetType.Arp);

                //_colorify.WriteLine($"{targetIp}", Colors.txtInfo);

                var arpPacket = new ArpPacket(
                    ArpOperation.Request,
                    broadcastMac,
                    targetIp,
                    attackerMac,
                    IPAddress.Parse(localIP)
                );

                ethernetPacket.PayloadPacket = arpPacket;
                device.SendPacket(ethernetPacket);

                Thread.Sleep(300);
            }

            return devices;
        }

        static HashSet<string> seenPackets = new HashSet<string>();
        static void Device_OnPacketArrival(object s, PacketCapture e)
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var arpPacket = packet.Extract<ArpPacket>();
            if ( arpPacket != null )
            {
                string sourceIp = arpPacket.SenderProtocolAddress.ToString();
                string sourceMac = arpPacket.SenderHardwareAddress.ToString();
                var data = arpPacket.Operation;
                string key = $"{sourceIp} -> {sourceMac}";

                if (!seenPackets.Contains(key))
                {
                    seenPackets.Add(key);
                    _colorify.WriteLine($"[{data}] Received ARP Packet: {sourceIp} -> {sourceMac}", Colors.txtSuccess);
                }
            }
        }

    }
}