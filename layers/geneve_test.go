// Copyright 2016 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"reflect"
	"testing"

	"github.com/davidsonff/gopacket"
)

var testPacketGeneve1 = []byte{
	0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0xfa, 0x16, 0x3e, 0x23, 0xd3, 0x42,
	0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x86, 0x87, 0x39, 0x40, 0x00,
	0x40, 0x11, 0x31, 0x35, 0xc0, 0xa8, 0x00, 0x53, 0xc0, 0xa8, 0x00, 0x55,
	0x31, 0x57, 0x17, 0xc1, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x65, 0x58,
	0x00, 0x00, 0x00, 0x00, 0xba, 0x09, 0x60, 0x5f, 0xa0, 0x91, 0xa2, 0xfe,
	0x54, 0x48, 0x88, 0x51, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x01, 0xf6,
	0x40, 0x00, 0x40, 0x01, 0xb7, 0x5f, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
	0x00, 0x02, 0x08, 0x00, 0x79, 0xdf, 0x0c, 0xfa, 0x63, 0xc4, 0x03, 0x0b,
	0x50, 0x58, 0x00, 0x00, 0x00, 0x00, 0xee, 0x2b, 0x0d, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
}

var testPacketGeneve2 = []byte{
	0x12, 0xbe, 0x4e, 0xb6, 0xa7, 0xc7, 0x02, 0x88, 0x0a, 0x81, 0xbd, 0x6d,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x86, 0x20, 0xf2, 0x00, 0x00, 0x40, 0x11,
	0x01, 0x52, 0xac, 0x10, 0x00, 0x01, 0xac, 0x10, 0x00, 0x02, 0x40, 0xa6,
	0x17, 0xc1, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x65, 0x58, 0x00, 0x00,
	0x0a, 0x00, 0xd2, 0x8c, 0xdb, 0x12, 0x53, 0xd5, 0x8e, 0xab, 0xa2, 0xa5,
	0x02, 0xf7, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x38, 0x1a, 0x40, 0x00,
	0x40, 0x01, 0x81, 0x3b, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
	0x08, 0x00, 0xdd, 0x9d, 0x7e, 0xde, 0x02, 0xc3, 0xcb, 0x07, 0x51, 0x58,
	0x00, 0x00, 0x00, 0x00, 0xba, 0x8d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
	0x34, 0x35, 0x36, 0x37,
}

var testPacketGeneve3 = []byte{
	0x00, 0x1b, 0x21, 0x3c, 0xac, 0x30, 0x00, 0x1b, 0x21, 0x3c, 0xab, 0x64, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x8e, 0xdf, 0xad, 0x40, 0x00, 0x40, 0x11, 0x32, 0xaf, 0x14, 0x00, 0x00, 0x01, 0x14, 0x00,
	0x00, 0x02, 0x31, 0x4a, 0x17, 0xc1, 0x00, 0x7a, 0x00, 0x00, 0x02, 0x40, 0x65, 0x58, 0x00, 0x00,
	0x0a, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0xfe, 0x71, 0xd8, 0x83, 0x72, 0x4f,
	0xb6, 0x9e, 0xd2, 0x49, 0x51, 0x48, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0xbd, 0xa2, 0x40, 0x00,
	0x40, 0x01, 0x41, 0x04, 0x1e, 0x00, 0x00, 0x01, 0x1e, 0x00, 0x00, 0x02, 0x08, 0x00, 0x2c, 0x54,
	0x29, 0x52, 0x00, 0x17, 0xf1, 0xa2, 0xce, 0x54, 0x00, 0x00, 0x00, 0x00, 0x17, 0x78, 0x0c, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
}

func TestDecodeGeneve1(t *testing.T) {
	p := gopacket.NewPacket(testPacketGeneve1, LinkTypeLinuxSLL, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{
		LayerTypeLinuxSLL, LayerTypeIPv4, LayerTypeUDP, LayerTypeGeneve,
		LayerTypeEthernet, LayerTypeIPv4, LayerTypeICMPv4, gopacket.LayerTypePayload,
	}, t)
	if got, ok := p.Layer(LayerTypeGeneve).(*Geneve); ok {
		want := &Geneve{
			BaseLayer: BaseLayer{
				Contents: testPacketGeneve1[44:52],
				Payload:  testPacketGeneve1[52:150],
			},
			Version:        0x0,
			OptionsLength:  0x0,
			OAMPacket:      false,
			CriticalOption: false,
			Protocol:       EthernetTypeTransparentEthernetBridging,
			VNI:            0x0,
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("Geneve layer mismatch, \nwant %#v\ngot  %#v\n", want, got)
		}
	}
}

func TestDecodeGeneve2(t *testing.T) {
	p := gopacket.NewPacket(testPacketGeneve2, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{
		LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeGeneve,
		LayerTypeEthernet, LayerTypeIPv4, LayerTypeICMPv4, gopacket.LayerTypePayload,
	}, t)
	if got, ok := p.Layer(LayerTypeGeneve).(*Geneve); ok {
		want := &Geneve{
			BaseLayer: BaseLayer{
				Contents: testPacketGeneve2[42:50],
				Payload:  testPacketGeneve2[50:148],
			},
			Version:        0x0,
			OptionsLength:  0x0,
			OAMPacket:      false,
			CriticalOption: false,
			Protocol:       EthernetTypeTransparentEthernetBridging,
			VNI:            0xa,
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("Geneve layer mismatch, \nwant %#v\ngot  %#v\n", want, got)
		}
	}
}

func TestDecodeGeneve3(t *testing.T) {
	p := gopacket.NewPacket(testPacketGeneve3, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{
		LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeGeneve,
		LayerTypeEthernet, LayerTypeIPv4, LayerTypeICMPv4, gopacket.LayerTypePayload,
	}, t)
	if got, ok := p.Layer(LayerTypeGeneve).(*Geneve); ok {
		want := &Geneve{
			BaseLayer: BaseLayer{
				Contents: testPacketGeneve3[42:58],
				Payload:  testPacketGeneve3[58:156],
			},
			Version:        0x0,
			OptionsLength:  0x8,
			OAMPacket:      false,
			CriticalOption: true,
			Protocol:       EthernetTypeTransparentEthernetBridging,
			VNI:            0xa,
			Options: []*GeneveOption{
				{
					Class:  0x0,
					Type:   0x80,
					Length: 8,
					Data:   []byte{0, 0, 0, 0xc},
				},
			},
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("Geneve layer mismatch, \nwant %#v\ngot  %#v\n", want, got)
		}
	}
}

func BenchmarkDecodeGeneve1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketGeneve1, LinkTypeEthernet, gopacket.NoCopy)
	}
}

func TestIsomorphicPacketGeneve(t *testing.T) {
	gn := &Geneve{
		Version:        0x0,
		OptionsLength:  0x14,
		OAMPacket:      false,
		CriticalOption: true,
		Protocol:       EthernetTypeTransparentEthernetBridging,
		VNI:            0xa,
		Options: []*GeneveOption{
			{
				Class:  0x0,
				Type:   0x80,
				Length: 12,
				Data:   []byte{0, 0, 0, 0, 0, 0, 0, 0xc},
			},
			{
				Class:  0x0,
				Type:   0x80,
				Length: 8,
				Data:   []byte{0, 0, 0, 0xc},
			},
		},
	}

	b := gopacket.NewSerializeBuffer()
	gn.SerializeTo(b, gopacket.SerializeOptions{})

	p := gopacket.NewPacket(b.Bytes(), gopacket.DecodeFunc(decodeGeneve), gopacket.Default)
	gnTranslated := p.Layer(LayerTypeGeneve).(*Geneve)
	gnTranslated.BaseLayer = BaseLayer{}

	if !reflect.DeepEqual(gn, gnTranslated) {
		t.Errorf("VXLAN isomorph mismatch, \nwant %#v\ngot %#v\n", gn, gnTranslated)
	}
}
