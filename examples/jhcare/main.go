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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/dumpcommand"
	"github.com/gopacket/gopacket/examples/util"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
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
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
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
	}
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	dumpcommand.Run(handle)
}

func Run(src gopacket.PacketDataSource) {

	var dot11 layers.Dot11
	var dot11Ctrl layers.Dot11Ctrl
	var Dot11Data layers.Dot11Data
	var Dot11Info layers.Dot11InformationElement
	var dot11MgmtProbeReq layers.Dot11MgmtProbeReq
	var dot11MgmtProbeResp layers.Dot11MgmtProbeResp
	var dot11MgmtBeacon layers.Dot11MgmtBeacon

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDot11, &dot11, &dot11Ctrl, &Dot11Data, &Dot11Info, &dot11MgmtProbeReq, &dot11MgmtProbeResp, &dot11MgmtBeacon)
	decoded := []gopacket.LayerType{}
	var dec gopacket.Decoder
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	count := 0
	start := time.Now()
	errors := 0
	truncated := 0
	layertypes := map[gopacket.LayerType]int{}

	for packet := range source.Packets() {
		count++

		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			log.Println("Error decoding layers:", err)
			continue
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeDot11:
				fmt.Printf("Dot11: %+v\n", dot11)
			case layers.LayerTypeDot11Ctrl:
				fmt.Printf("Dot11Ctrl: %+v\n", dot11Ctrl)
			case layers.LayerTypeDot11Data:
				fmt.Printf("Dot11Data: %+v\n", Dot11Data)
			case layers.LayerTypeDot11InformationElement:
				fmt.Printf("Dot11InformationElement: %+v\n", Dot11Info)
			case layers.LayerTypeDot11MgmtProbeReq:
				fmt.Printf("Dot11MgmtProbeReq: %+v\n", dot11MgmtProbeReq)
			case layers.LayerTypeDot11MgmtProbeResp:
				fmt.Printf("Dot11MgmtProbeResp: %+v\n", dot11MgmtProbeResp)
			case layers.LayerTypeDot11MgmtBeacon:
				fmt.Printf("Dot11MgmtBeacon: %+v\n", dot11MgmtBeacon)
			default:
				fmt.Printf("Other Layer: %s\n", layerType)
			}
		}
		for _, layer := range packet.Layers() {
			layertypes[layer.LayerType()]++
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
