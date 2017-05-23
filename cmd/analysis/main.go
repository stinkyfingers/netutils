package main

import (
	"flag"
	"log"
	"os"

	"github.com/stinkyfingers/netutils/pcapio"
)

var (
	path            = flag.String("f", "", "file path")
	output          = flag.String("o", "", "output path")
	tcp             = flag.Bool("tcp", false, "incl tcp layer")
	ip              = flag.Bool("ip", false, "incl ip layer")
	eth             = flag.Bool("eth", false, "incl eth layer")
	individual      = flag.Bool("ind", false, "stdout each payload as they are decoded")
	extractPayloads = flag.String("ex", "", "extract payloads")
)

func main() {
	flag.Parse()

	// decode and print
	if *individual {
		err := pcapio.AnalyzeIndividually(*path, *eth, *ip, *tcp)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if *extractPayloads != "" {
		payloads, err := pcapio.ExtractPayload(*path, *extractPayloads)
		if err != nil {
			log.Fatal(err)
		}

		for i, payload := range payloads {
			log.Println("Payload ", i)
			log.Println(payload)
		}
		return
	}

	str, err := pcapio.AnalyzePayloadLayer(*path, *eth, *ip, *tcp)
	if err != nil {
		log.Fatal(err)
	}
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			log.Fatal(err)
		}
		_, err = f.Write([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Print(str)
	}

}
