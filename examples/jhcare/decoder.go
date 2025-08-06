package main

import (
	"github.com/davidsonff/gopacket"
)

// L80211Layer is the layer type for 802.11 probe requests.
var L80211Layer = gopacket.RegisterLayerType(12345, gopacket.LayerTypeMetadata{Name: "802.11 Probe Request", Decoder: gopacket.DecodeFunc(decode80211Layer)})

// Now implement a decoder... this one strips off the first 4 bytes of the
// packet.
func decode80211Layer(data []byte, p gopacket.PacketBuilder) error {
	// Create 802.11 layer

	m, err := ParseProbeRequest(data)
	if err != nil {
		return err
	}

	p.AddLayer(m)

	return nil
}
