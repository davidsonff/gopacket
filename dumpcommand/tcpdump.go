// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package dumpcommand implements a run function for pfdump and pcapdump
// with many similar flags/features to tcpdump.  This code is split out seperate
// from data sources (pcap/pfring) so it can be used by both.
package dumpcommand

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/ip4defrag"
	"github.com/gopacket/gopacket/layers"
)

var (
	print       = flag.Bool("print", true, "Print out packets, if false only prints out statistics")
	maxcount    = flag.Int("c", -1, "Only grab this many packets, then exit")
	decoder     = flag.String("decoder", "Ethernet", "Name of the decoder to use")
	dump        = flag.Bool("X", false, "If true, dump very verbose info on each packet")
	statsevery  = flag.Int("stats", 1000, "Output statistics every N packets")
	printErrors = flag.Bool("errors", false, "Print out packet dumps of decode errors, useful for checking decoders against live traffic")
	lazy        = flag.Bool("lazy", false, "If true, do lazy decoding")
	defrag      = flag.Bool("defrag", false, "If true, do IPv4 defrag")
)

func Run(src gopacket.PacketDataSource) {
	if !flag.Parsed() {
		log.Fatalln("Run called without flags.Parse() being called")
	}
	var dec gopacket.Decoder
	var ok bool
	if dec, ok = gopacket.DecodersByLayerName["Dot11Ctrl"]; !ok {
		log.Fatalln("No decoder named", *decoder)
	}
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = *lazy
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	fmt.Fprintln(os.Stderr, "Starting to read packets")
	count := 0
	bytes := int64(0)
	start := time.Now()
	errors := 0
	truncated := 0
	layertypes := map[gopacket.LayerType]int{}
	defragger := ip4defrag.NewIPv4Defragmenter()

	for packet := range source.Packets() {
		count++
		bytes += int64(len(packet.Data()))

		// defrag the IPv4 packet if required
		if *defrag {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer == nil {
				continue
			}
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length

			newip4, err := defragger.DefragIPv4(ip4)
			if err != nil {
				log.Fatalln("Error while de-fragmenting", err)
			} else if newip4 == nil {
				continue // packet fragment, we don't have whole packet yet.
			}
			if newip4.Length != l {
				fmt.Printf("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		if *dump {

			dot11Layer := packet.Layer(layers.LayerTypeDot11)
			if dot11Layer != nil {
				dot11 := dot11Layer.(*layers.Dot11)
				fmt.Printf("Dot11: %+v\n", dot11)
			}

			for _, layer := range packet.Layers() {
				switch l := layer.(type) {
				case *layers.Dot11:
					fmt.Printf("Dot11: %+v\n", l)
				case *layers.Dot11MgmtProbeReq:
					fmt.Printf("Dot11MgmtProbeReq: %+v\n", l)
				case *layers.Dot11MgmtProbeResp:
					fmt.Printf("Dot11MgmtProbeResp: %+v\n", l)
				case *layers.Dot11MgmtBeacon:
					fmt.Printf("Dot11MgmtBeacon: %+v\n", l)
				// case *layers.Dot11MgmtAssocReq:
				// 	fmt.Printf("Dot11MgmtAssocReq: %+v\n", l)
				// case *layers.Dot11MgmtAssocResp:
				// 	fmt.Printf("Dot11MgmtAssocResp: %+v\n", l)
				// case *layers.Dot11MgmtAuth:
				// 	fmt.Printf("Dot11MgmtAuth: %+v\n", l)
				default:
					// Optionally print other layers
					fmt.Printf("%s\n", packet.Dump())
				}
			}
			fmt.Println()
		} else if *print {

			dot11Layer := packet.Layer(layers.LayerTypeDot11)
			if dot11Layer != nil {
				//dot11 := dot11Layer.(*layers.Dot11)
				//fmt.Printf("Dot11: %+v\n", dot11)
			}

			for _, layer := range packet.Layers() {
				switch l := layer.(type) {
				//	case *layers.Dot11:
				//		fmt.Printf("Dot11\n")
				case *layers.Dot11MgmtProbeReq:
					fmt.Printf("Dot11MgmtProbeReq: %+v\n", l)
				case *layers.Dot11MgmtProbeResp:
					fmt.Printf("Dot11MgmtProbeResp: %+v\n", l)
				case *layers.Dot11MgmtBeacon:
					fmt.Printf("Dot11MgmtBeacon: %+v\n", l)
				//case *layers.Dot11MgmtAssociationReq:
				//	fmt.Printf("Dot11MgmtAssociationReq\n")
				//case *layers.Dot11InformationElement:
				//	fmt.Printf("Dot11InformationElement: %+v\n", l)
				// case *layers.Dot11MgmtAssocResp:
				// 	fmt.Printf("Dot11MgmtAssocResp: %+v\n", l)
				// case *layers.Dot11MgmtAuth:
				// 	fmt.Printf("Dot11MgmtAuth: %+v\n", l)
				default:
					// Optionally print other layers
					//fmt.Printf("%s\n", packet.Dump())
				}
			}
		}
		if !*lazy || *print || *dump { // if we've already decoded all layers...
			for _, layer := range packet.Layers() {
				layertypes[layer.LayerType()]++
			}
			if packet.Metadata().Truncated {
				truncated++
			}
			if errLayer := packet.ErrorLayer(); errLayer != nil {
				errors++
				if *printErrors {
					fmt.Println("Error:", errLayer.Error())
					fmt.Println("--- Packet ---")
					fmt.Println(packet.Dump())
				}
			}
		}
		done := *maxcount > 0 && count >= *maxcount
		if count%*statsevery == 0 || done {
			fmt.Fprintf(os.Stderr, "Processed %v packets (%v bytes) in %v, %v errors and %v truncated packets\n", count, bytes, time.Since(start), errors, truncated)
			if len(layertypes) > 0 {
				fmt.Fprintf(os.Stderr, "Layer types seen: %+v\n", layertypes)
			}
		}
		if done {
			break
		}
	}
}
