package jhcare

import (
	"fmt"
	"log"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func Run(src gopacket.PacketDataSource) {

	var dot11 layers.Dot11
	var dot11Ctrl layers.Dot11Ctrl
	var dot11MgmtProbeReq layers.Dot11MgmtProbeReq
	var dot11MgmtProbeResp layers.Dot11MgmtProbeResp
	var dot11MgmtBeacon layers.Dot11MgmtBeacon

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDot11, &dot11, &dot11Ctrl, &dot11MgmtProbeReq, &dot11MgmtProbeResp, &dot11MgmtBeacon)
	decoded := []gopacket.LayerType{}
	var dec gopacket.Decoder
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	for packet := range source.Packets() {
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
	}
}
