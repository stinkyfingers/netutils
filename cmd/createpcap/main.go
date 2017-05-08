package main

import (
	"flag"
	"log"

	"github.com/stinkyfingers/netutils/pcapcreation"
)

var (
	path = flag.String("p", "", "json file for pcap payload")
	out  = flag.String("o", "", "output pcap path")
)

func main() {
	flag.Parse()

	data, err := pcapcreation.ImportPayloads(*path)
	if err != nil {
		log.Fatal(err)
	}

	err = pcapcreation.WritePayloadsToFile(data, *out)
	if err != nil {
		log.Fatal(err)
	}

}
