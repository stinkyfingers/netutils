package pcapio

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// AnalyzePayload returns the payload for a single pcap for the specified OSI-ish layer
func AnalyzePayload(path string) (string, error) {
	var out string
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return out, err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, err
		}

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			out += PrintEth(ethLayer.(*layers.Ethernet))
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			out += PrintIPv4(ipv4Layer.(*layers.IPv4))
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			out += PrintTCP(tcpLayer.(*layers.TCP))
		}

	}

	return out, nil
}

func PrintTCP(packet *layers.TCP) string {
	var out string
	out += fmt.Sprintln("TCP Packet: ", packet)
	out += fmt.Sprintf("SrcPort: %v\n", packet.SrcPort)
	out += fmt.Sprintf("DstPort: %v\n", packet.DstPort)
	out += fmt.Sprintf("Seq: %d\n", packet.Seq)
	out += fmt.Sprintf("Ack: %d\n", packet.Ack)
	out += fmt.Sprintf("DataOffset: %d\n", packet.DataOffset)
	out += fmt.Sprintf("FIN: %t\n", packet.FIN)
	out += fmt.Sprintf("SYN: %t\n", packet.SYN)
	out += fmt.Sprintf("RST: %t\n", packet.RST)
	out += fmt.Sprintf("PSH: %t\n", packet.PSH)
	out += fmt.Sprintf("ACK: %t\n", packet.ACK)
	out += fmt.Sprintf("URG: %t\n", packet.URG)
	out += fmt.Sprintf("ECE: %t\n", packet.ECE)
	out += fmt.Sprintf("CWR: %t\n", packet.CWR)
	out += fmt.Sprintf("NS: %t\n", packet.NS)
	out += fmt.Sprintf("Window: %d\n", packet.Window)
	out += fmt.Sprintf("Checksum: %d\n", packet.Checksum)
	out += fmt.Sprintf("Urgent: %d\n", packet.Urgent)
	for _, opt := range packet.Options {
		out += fmt.Sprintf("Option: %s\n", opt.String())
	}
	for _, pad := range packet.Padding {
		out += fmt.Sprintf("Option: %t\n", pad)
	}
	out += fmt.Sprintf("DATA: %d\n", packet.Payload)

	out += fmt.Sprintln("")
	return out
}

func PrintEth(frame *layers.Ethernet) string {
	var out string
	out += fmt.Sprintln("Frame: ", frame)
	out += fmt.Sprintf("SrcMAC: %d\n", frame.SrcMAC)
	out += fmt.Sprintf("DstMAC: %d\n", frame.DstMAC)
	out += fmt.Sprintf("EthernetType: %d\n", frame.EthernetType)
	out += fmt.Sprintf("Length: %d\n", frame.Length)
	out += fmt.Sprintf("DATA: %d\n", frame.Payload)

	out += fmt.Sprintln("")
	return out
}

func PrintIPv4(packet *layers.IPv4) string {
	var out string
	out += fmt.Sprintln("Packet: ", packet)
	out += fmt.Sprintf("Version: %d\n", packet.Version)
	out += fmt.Sprintf("IHL: %d\n", packet.IHL)
	out += fmt.Sprintf("TOS: %d\n", packet.TOS)
	out += fmt.Sprintf("Length(TL): %d\n", packet.Length)
	out += fmt.Sprintf("Id: %d\n", packet.Id)
	out += fmt.Sprintf("Flags: %d\n", packet.Flags)
	out += fmt.Sprintf("FragOffset: %d\n", packet.FragOffset)
	out += fmt.Sprintf("TTL: %d\n", packet.TTL)
	out += fmt.Sprintf("Protocol: %d\n", packet.Protocol)
	out += fmt.Sprintf("Checksum: %d\n", packet.Checksum)
	out += fmt.Sprintf("SrcIP: %d\n", packet.SrcIP)
	out += fmt.Sprintf("DstIP: %d\n", packet.DstIP)
	out += fmt.Sprintf("Options: %d\n", packet.Options)
	out += fmt.Sprintf("Padding: %d\n", packet.Padding)
	out += fmt.Sprintf("DATA: %d\n", packet.Payload)

	out += fmt.Sprintln("")
	return out
}

// Seq - Sequences & data
func SeqDataTCP(path string) (string, error) {
	var out string
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return out, err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, err
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			out += PrintTCPSeqData(tcpLayer.(*layers.TCP))
		}

	}
	return out, nil
}

func PrintTCPSeqData(packet *layers.TCP) string {
	var out string
	out += fmt.Sprintf("Seq:      %d\n", packet.Seq)
	out += fmt.Sprintf("Len Data: %d\n", len(packet.Payload))
	out += fmt.Sprintf("Next seq: %d\n", packet.Seq+uint32(len(packet.Payload)))

	out += fmt.Sprintln("")
	return out
}
