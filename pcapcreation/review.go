package pcapcreation

// examine payloads written, without tcpassembly

import (
	"errors"
	"io"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ExtractPayload returns the payload for a single pcap for the specified OSI-ish layer
func ExtractPayload(path, layer string) ([][]byte, error) {
	var payloads [][]byte
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return payloads, err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// tcp sort
	var tcpsort []*layers.TCP

	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			return payloads, err
		}

		switch layer {
		case "ipv4":
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				if len(ipv4Layer.LayerPayload()) > 0 {
					payloads = append(payloads, ipv4Layer.LayerPayload())
				}
			}
		case "tcpsort":
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				if ipv4Layer.(*layers.IPv4).FragOffset != 0 {
					return nil, errors.New("unhandled - ip layer is fragmented")
				}
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if len(tcpLayer.(*layers.TCP).LayerPayload()) > 0 {
					tcpsort = append(tcpsort, tcpLayer.(*layers.TCP))
				}
			}
		case "tcpjoin":
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				if ipv4Layer.(*layers.IPv4).FragOffset != 0 {
					return nil, errors.New("unhandled - ip layer is fragmented")
				}
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if len(tcpLayer.(*layers.TCP).LayerPayload()) > 0 {
					tcpsort = append(tcpsort, tcpLayer.(*layers.TCP))
				}
			}

		case "tcp":
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if len(tcpLayer.LayerPayload()) > 0 {
					payloads = append(payloads, tcpLayer.LayerPayload())
				}
			}
		case "tcpsession":
			if len(payloads) == 0 {
				payloads = make([][]byte, 1)
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if len(tcpLayer.LayerPayload()) > 0 {
					payloads[0] = append(payloads[0], tcpLayer.LayerPayload()...)
				}
			}
		case "udp":
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				if len(udpLayer.LayerPayload()) > 0 {
					payloads = append(payloads, udpLayer.LayerPayload())
				}
			}

		default:
			return payloads, errors.New("layer type is not supported.")
		}
	}

	// finish
	switch layer {
	case "tcpsort":
		payloads = SortTcpPackets(tcpsort)
	case "tcpjoin":
		payloads = SortAndJoinTcpPackets(tcpsort)

	default:
	}

	return payloads, nil
}

// SortTcpPackets attempts to organize packets based on TCP seq
func SortTcpPackets(tcpLayer []*layers.TCP) [][]byte {
	var sorted [][]byte

	lowestSeq := int(tcpLayer[0].Seq) // 1st packet
	var keys []int

	packetMap := make(map[int]*layers.TCP)
	for _, packet := range tcpLayer {
		packetMap[int(packet.Seq)] = packet
		if int(packet.Seq) < lowestSeq {
			lowestSeq = int(packet.Seq)
		}
		keys = append(keys, int(packet.Seq))
	}

	sort.Ints(keys)

	for k := range keys {
		sorted = append(sorted, packetMap[keys[k]].LayerPayload())
	}

	return sorted
}

// SortAndJoinTcpPackets attempts to organize packets based on TCP seq and join consecutive sequences
func SortAndJoinTcpPackets(tcpLayer []*layers.TCP) [][]byte {
	var joined [][]byte

	lowestSeq := int(tcpLayer[0].Seq) // 1st packet
	var keys []int

	packetMap := make(map[int]*layers.TCP)
	for _, packet := range tcpLayer {
		packetMap[int(packet.Seq)] = packet
		if int(packet.Seq) < lowestSeq {
			lowestSeq = int(packet.Seq)
		}
		keys = append(keys, int(packet.Seq))
	}

	sort.Ints(keys)

	for k := range keys {
		if k == 0 {
			joined = append(joined, packetMap[keys[0]].LayerPayload())
			continue
		}
		keyFromPrev := int(packetMap[keys[k-1]].Seq) + len(packetMap[keys[k-1]].LayerPayload())
		if packet, ok := packetMap[keyFromPrev]; ok {
			joined[len(joined)-1] = append(joined[len(joined)-1], packet.LayerPayload()...)
		} else {
			packet = packetMap[keys[k]]
			joined = append(joined, packet.LayerPayload())
		}
	}

	return joined
}
