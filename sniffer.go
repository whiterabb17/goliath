package goliath

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	device      string
	snapshotLen int32
	promiscuous bool
	timeOut     = 30 * time.Second
	handle      *pcap.Handle
	packetCount int
	layer       layers.LinkType
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions
	ethLayer    layers.Ethernet
	ipLayer     layers.IPv4
	tcpLayer    layers.TCP
	err         error
)

func ListDevices() string {
	devices, err := pcap.FindAllDevs()
	var ifaces string
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("List of Devices Found:")
		ifaces = "List of Devices Found: \n"
		for _, device := range devices {
			fmt.Println("Name:", device.Name)
			ifaces += "Name: " + device.Name + " \n"
			fmt.Println("Description:", device.Description)
			ifaces += "Description: " + device.Description + "\n"
			fmt.Println("Addresses:", device.Addresses)
			ifaces += "Addresses: \n"
			for _, address := range device.Addresses {
				fmt.Println("\t - IP Address:", address.IP)
				ifaces += "\t - IP Address: " + string(address.IP) + "\n"
				fmt.Println("\t - Subnet Mask:", address.Netmask)
				ifaces += "\t - Subnet Mask: " + string(address.Netmask) + "\n"
			}

			fmt.Println()
		}
	}
	writeLog(ifaces, "NetworkInterfaces")
	return ifaces
}

func LiveCapture(collect bool) {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeOut)
	var dumpedPackets string
	if err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()
		f, _ := os.Create(time.Now().Format("2006-01-02 3:4:5") + "Capture.pcap")
		w := pcapgo.NewWriter(f)

		_ = w.WriteFileHeader(uint32(snapshotLen), layer)

		defer f.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			fmt.Println(packet)
			dumpedPackets += "\n\n====================================================================================================\n" + packet.Dump() + "\n====================================================================================================\n\n"
			if collect {
				writeLog(dumpedPackets, "PacketDump")
			}
		}
	}
}

func writeLog(input string, file string) {
	f, err := os.Create(file + ".log")

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	_, err2 := f.WriteString(input)

	if err2 != nil {
		log.Fatal(err2)
	}

	fmt.Println("done")
}

func WritingToPCAPFile(filter string) {
	f, _ := os.Create(time.Now().Format("2006-01-02 3:4:5") + "Capture.pcap")
	w := pcapgo.NewWriter(f)

	_ = w.WriteFileHeader(uint32(snapshotLen), layer)

	defer f.Close()

	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeOut)

	if err != nil {
		fmt.Printf("\nError Opening Device %s: %v", device, err)
		os.Exit(1)
	}

	defer handle.Close()

	if filter != "" {
		err = handle.SetBPFFilter(filter)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Capturing Packets with filter:", filter)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	count := 0

	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		count++

		if count > packetCount {
			break
		}
	}
}

func OpenPCAP(pcapFile string) {
	fmt.Println("File: ", pcapFile)
	handle, err = pcap.OpenOffline(pcapFile)

	if err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			fmt.Println(packet)
		}
	}
}

func UsingFilters(filers string) {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeOut)

	if err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()

		err = handle.SetBPFFilter(filers)

		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Println("Capturing Packets with Filer:", filers)

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packetSource.Packets() {
				fmt.Println(packet)
			}
		}
	}
}

func PacketInfo(packet gopacket.Packet) {
	// Check for Ethernet Packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

	if ethernetLayer != nil {
		fmt.Println("Ethernet Layer Detected")

		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		fmt.Println("Source MAC:", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC:", ethernetPacket.DstMAC)
		fmt.Println("Ethernet Type:", ethernetPacket.EthernetType)
		fmt.Println("Payload:", string(ethernetPacket.Payload))
		fmt.Println()
	}

	// Check for IPv4 Packet
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if ipLayer != nil {
		fmt.Println("IPv4 Layer Detected")

		ipPacket, _ := ipLayer.(*layers.IPv4)

		fmt.Println("Source IP:", ipPacket.SrcIP)
		fmt.Println("Destination IP:", ipPacket.DstIP)
		fmt.Println("Protocol:", ipPacket.Protocol)
		fmt.Println("Payload:", string(ipPacket.Payload))
		fmt.Println()
	}

	// Check for IPv4 Packet
	ipLayer = packet.Layer(layers.LayerTypeIPv6)

	if ipLayer != nil {
		fmt.Println("IPv6 Layer Detected")

		ipPacket, _ := ipLayer.(*layers.IPv6)

		fmt.Println("Source IP:", ipPacket.SrcIP)
		fmt.Println("Destination IP:", ipPacket.DstIP)
		fmt.Println("Payload:", string(ipPacket.Payload))
		fmt.Println()
	}

	// Check for TCP Packet
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer != nil {
		fmt.Println("TCP Layer Detected")

		tcpLayer, _ := tcpLayer.(*layers.TCP)

		fmt.Println("Source Port:", tcpLayer.SrcPort)
		fmt.Println("Destination Port:", tcpLayer.DstPort)
		fmt.Println("Sequence Number:", tcpLayer.Seq)
		fmt.Println("Payload:", string(tcpLayer.Payload))
		fmt.Println()
	}

	// Check for Application Layer
	applicationLayer := packet.ApplicationLayer()

	if applicationLayer != nil {
		fmt.Println("Application Layer/Payload Found")
		fmt.Printf("%s\n", applicationLayer.Payload())

		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP Found!")
		}
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet", err)
	}
}

func GetPacketInfo() {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeOut)

	if err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			PacketInfo(packet)
		}
	}
}

func CreatingPacket(payload string) {
	rawPacket := []byte(payload)

	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, &ethLayer, &ipLayer, &tcpLayer, gopacket.Payload(rawPacket))
	outgoingPacket := buffer.Bytes()

	fmt.Println("Sending your created Packet")
	err = handle.WritePacketData(outgoingPacket)

	if err != nil {
		fmt.Println(err)
	}
}

func DecodingPacket() {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeOut)

	if err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			parser := gopacket.NewDecodingLayerParser(
				gopacket.LayerType(layer),
				&ethLayer,
				&ipLayer,
				&tcpLayer,
			)

			var foundLayerTypes []gopacket.LayerType

			err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)

			if err != nil {
				fmt.Println("Trouble Decoding Layers:", err)
			}

			for _, layerType := range foundLayerTypes {
				if layerType == layers.LayerTypeIPv4 {
					fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				} else if layerType == layers.LayerTypeIPv6 {
					fmt.Println("IPv6: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				} else if layerType == layers.LayerTypeTCP {
					fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
					fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
				}
			}
		}
	}
}

func Decoder() {
	fmt.Println("Enter Device to Use:")
	fmt.Scanln(&device)

	fmt.Println("Enter Snapshot Length(Min: 1024, Max: 65535):")
	fmt.Scanln(&snapshotLen)

	if snapshotLen < 1024 || snapshotLen > 65535 {
		snapshotLen = 1024
	}

	var c string
	fmt.Println("Promiscuous Mode(N):")
	fmt.Scanln(&c)

	if c == "Y" || c == "y" {
		promiscuous = true
	} else if c == "N" || c == "n" {
		promiscuous = false
	}

	DecodingPacket()
}

func SharkWire(iface string, slen string, promisc bool, keep bool) {
	device = iface
	var snapshotLen int
	snapshotLen, err = strconv.Atoi(slen)
	if err != nil {
		log.Println(err)
	}
	if snapshotLen < 1024 || snapshotLen > 65535 {
		snapshotLen = 1024
	}
	promiscuous = promisc
	LiveCapture(keep)
}

func SharkWireW(iface string, slen string, promisc bool, filter string) {
	device = iface
	snapshotLen, err := strconv.Atoi(slen)
	if err != nil {
		log.Println(err)
	}
	if snapshotLen < 1024 || snapshotLen > 65535 {
		snapshotLen = 1024
	}

	promiscuous = promisc

	layer = layers.LinkTypeIPv4

	UsingFilters(filter)

	WritingToPCAPFile(filter)

	fmt.Println("Process Completed!")
}
