// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/davidsonff/gopacket"
	"github.com/davidsonff/gopacket/examples/util"
	"github.com/davidsonff/gopacket/layers"
	"github.com/davidsonff/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = true

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// This is a little complicated because we want to allow all possible options
	// for creating the packet capture handle... instead of all this you can
	// just call pcap.OpenLive if you want a simple handle.
	inactive, err := pcap.NewInactiveHandle(*iface)
	if err != nil {
		log.Fatalf("could not create: %v", err)
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(*snaplen); err != nil {
		log.Fatalf("could not set snap length: %v", err)
	} else if err = inactive.SetPromisc(promisc); err != nil {
		log.Fatalf("could not set promisc mode: %v", err)
	} else if err = inactive.SetTimeout(pcap.BlockForever); err != nil {
		log.Fatalf("could not set timeout: %v", err)
	}
	if *tstype != "" {
		if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
			log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
		} else if err := inactive.SetTimestampSource(t); err != nil {
			log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
		}
	}
	if handle, err = inactive.Activate(); err != nil {
		log.Fatal("PCAP Activate error:", err)
	}
	defer handle.Close()

	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	//packetSource := gopacket.NewPacketSource(handle)
	Run(handle)
}

func Run(src *pcap.Handle) {

	//var dot11 layers.Dot11
	//var dot11Ctrl layers.Dot11Ctrl
	//var Dot11Data layers.Dot11Data
	//var Dot11MgmtAssociationReq layers.Dot11MgmtAssociationReq
	var dot11MgmtProbeReq layers.Dot11MgmtProbeReq
	var Dot11Info layers.Dot11InformationElement
	//var dot11MgmtProbeResp layers.Dot11MgmtProbeResp
	//var dot11MgmtBeacon layers.Dot11MgmtBeacon

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDot11, &dot11MgmtProbeReq, &Dot11Info)
	decoded := []gopacket.LayerType{}
	var dec gopacket.Decoder
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = true
	source.NoCopy = false
	source.DecodeStreamsAsDatagrams = true

	count := 0
	start := time.Now()
	errors := 0
	truncated := 0
	layertypes := map[gopacket.LayerType]int{}

	for packet := range source.Packets() {
		count++

		_ = parser.DecodeLayers(packet.Data(), &decoded)

		for _, layer := range decoded {

			switch layer {
			case layers.LayerTypeDot11:
				//			fmt.Printf("Dot11 add1: %+v, add2 %v, add3 %v, add4 %v, type: %v\n", dot11.Address1, dot11.Address2, dot11.Address3, dot11.Address4, dot11.Type)
			case layers.LayerTypeDot11Ctrl:
				fmt.Printf("Dot11Ctrl package\n")
			case layers.LayerTypeDot11Data:
				fmt.Printf("Dot11Data package\n")
			// case layers.LayerTypeDot11MgmtAssociationReq:
			// 	fmt.Printf("Dot11MgmtAssociationReq package\n")
			case layers.LayerTypeDot11InformationElement:
				fmt.Printf("Dot11InformationElement: %+v\n", Dot11Info.String())
			case layers.LayerTypeDot11MgmtProbeReq:
				fmt.Printf("Dot11MgmtProbeReq: %v\n", string(dot11MgmtProbeReq.LayerContents()))
			case layers.LayerTypeDot11MgmtProbeResp:
				fmt.Printf("Dot11MgmtProbeResp\n")
			case layers.LayerTypeDot11MgmtBeacon:
				fmt.Printf("Dot11MgmtBeacon\n")
			default:
				fmt.Printf("Other Layer: %s\n", layer.String())
			}
			layertypes[layer]++
		}

		if packet.Metadata().Truncated {
			truncated++
		}

		if errLayer := packet.ErrorLayer(); errLayer != nil {
			errors++

			fmt.Println("Error:", errLayer.Error())
			fmt.Println("--- Packet ---")
			fmt.Println(packet.Dump())

		}

		if count%1000 == 0 {
			fmt.Fprintf(os.Stderr, "Processed %v packets in %v, %v errors and %v truncated packets\n", count, time.Since(start), errors, truncated)
			if len(layertypes) > 0 {
				fmt.Fprintf(os.Stderr, "Layer types seen: %+v\n", layertypes)
			}
		}
	}
}
