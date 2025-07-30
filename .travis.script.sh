#!/bin/bash

set -ev

go test github.com/davidsonff/gopacket
go test github.com/davidsonff/gopacket/layers
go test github.com/davidsonff/gopacket/tcpassembly
go test github.com/davidsonff/gopacket/reassembly
go test github.com/davidsonff/gopacket/pcapgo
go test github.com/davidsonff/gopacket/pcap
sudo $(which go) test github.com/davidsonff/gopacket/routing
