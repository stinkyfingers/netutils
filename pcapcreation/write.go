package pcapcreation

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Payload creation from JSON files
// Example:
// [
// 	{"payload":"0,1,2,3,4,5,6,7,8,9"},
// 	{"payload":"10,11,12,13,14,15,16,17,18,19"},
// 	{"payload":"20,21,22,23,24,25,26,27,28,29"}
// ]
// name file with content above seqs.json
// payloads := ImportPayloads(seqs.json)
// err := WritePayloadsToFile(payloads, myfile.pcap)

type PayloadDatum struct {
	Payload string `json:"payload"`
}

type PayloadData []PayloadDatum

// ImportPayloads takes a JSON file and converts to [][]byte, for passing to WritePayloadsToFile
func ImportPayloads(path string) ([][]byte, error) {
	var payloads [][]byte
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var data PayloadData

	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return nil, err
	}

	for _, datum := range data {
		var payload []byte
		arr := strings.Split(datum.Payload, ",")
		for _, a := range arr {
			i, err := strconv.Atoi(a)
			if err != nil {
				return nil, err
			}

			payload = append(payload, byte(i))
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

// WritePayloadsToFile creates packets from raw bytes ([][]byte) and writes them as pcaps
func WritePayloadsToFile(payloads [][]byte, path string) error {
	var packets [][]byte
	var previousLen int
	var fin bool
	for i, payload := range payloads {
		//fin
		if i == len(payloads)-1 {
			fin = true
		}
		//seq
		if i > 0 {
			previousLen += len(payloads[i-1])
		}
		packet, err := CreatePacket(payload, i, fin, previousLen)
		if err != nil {
			return err
		}
		packets = append(packets, packet)
	}

	return WritePackets(packets, path)

}

// CreatePacket returns a []byte datagram
func CreatePacket(data []byte, seq int, fin bool, previousLen int) ([]byte, error) {
	inter, err := net.InterfaceByName("en0")
	if err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	eth := &layers.Ethernet{
		SrcMAC: inter.HardwareAddr,
		DstMAC: inter.HardwareAddr,
	}
	eth.EthernetType = layers.EthernetTypeIPv4

	ip := &layers.IPv4{
		SrcIP: net.IP{10, 10, 10, 10},
		DstIP: net.IP{192, 168, 0, 1},
	}
	ip.Protocol = layers.IPProtocolTCP
	ip.IHL = 5 // TODO - always 5 bytes???

	tcp := &layers.TCP{
		SrcPort: 8000,
		DstPort: 9000,
		Seq:     uint32(seq + previousLen),
		Ack:     1,
		PSH:     true,
		Window:  2,
		BaseLayer: layers.BaseLayer{
			Payload: data,
		},
		DataOffset: 5, //TODO aloways 5??
		FIN:        fin,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	// ip.Length = 20 + uint16(len(tcp.Payload)) //TODO ???
	payload := gopacket.Payload(data) // TODO

	gopacket.SerializeLayers(buf, opts,
		eth,
		ip,
		tcp,
		payload)
	packetData := buf.Bytes()
	return packetData, nil
}

// WritePackets writes Datagrams (as [][]byte) to file
func WritePackets(data [][]byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1024, layers.LinkTypeEthernet)

	for _, packetData := range data {
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(packetData), CaptureLength: len(packetData)}
		err = w.WritePacket(ci, packetData)
		if err != nil {
			return err
		}
	}
	return nil
}

// WritePacket writes a Datagram (as []byte) to file
func WritePacket(data []byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1024, layers.LinkTypeEthernet)

	ci := gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(data), CaptureLength: len(data)}
	return w.WritePacket(ci, data)
}
