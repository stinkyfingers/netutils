package pcapio

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

//https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go

type streamFactory struct {
	reassembly []tcpassembly.Reassembly
	payloads   [][]byte
}

func (s *streamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	return s
}

func (s *streamFactory) Reassembled(r []tcpassembly.Reassembly) {
	s.reassembly = r
	for i := range r {
		log.Print(r[i].Bytes)
		if len(s.payloads) == 0 {
			s.payloads = [][]byte{r[i].Bytes}
		} else {
			s.payloads[0] = append(s.payloads[0], r[i].Bytes...)
		}
	}
}

func (s *streamFactory) ReassemblyComplete() {
}

// GetFiles walks the path and returns files
// ignores non .pcaps
func GetFiles(path string) ([]string, error) {
	var files []string
	walkFn := filepath.WalkFunc(func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".pcap" {
			return nil
		}
		files = append(files, path)
		return nil
	})

	err := filepath.Walk(path, walkFn)
	return files, err
}

// ExtractPayload returns the payload for a single pcap for the specified OSI-ish layer
func ExtractPayload(path, layer string) ([][]byte, error) {
	var payloads [][]byte
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return payloads, err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// tcp stream reassembly
	factory := &streamFactory{}
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)
	defer assembler.FlushAll()

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
		case "tcpstream":
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
				continue
			}

			tcp := packet.TransportLayer().(*layers.TCP)
			factory.reassembly = []tcpassembly.Reassembly{}
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

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
	case "tcpstream":
		assembler.FlushAll()
		payloads = factory.payloads
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
