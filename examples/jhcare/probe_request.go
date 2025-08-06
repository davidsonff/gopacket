package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/davidsonff/gopacket"
)

// ProbeRequest represents an 802.11 Probe Request frame.
type ProbeRequest struct {
	// Frame Control fields are typically handled by libraries like gopacket.
	// For a simplified struct focusing on the request itself,
	// the detailed Frame Control fields are omitted.

	// Duration/ID field (2 bytes)
	Duration uint16

	// Destination Address (DA) - 6 bytes (usually broadcast, ff:ff:ff:ff:ff:ff for Probe Request)
	// It's the address of the device or AP the probe is intended for.
	DestinationAddress net.HardwareAddr

	// Source Address (SA) - 6 bytes (the MAC address of the device sending the request)
	SourceAddress net.HardwareAddr

	// BSSID (Basic Service Set Identifier) - 6 bytes (often the same as SourceAddress for clients)
	// For Probe Requests, it's often set to a broadcast address.
	BSSID net.HardwareAddr

	// Sequence Control (2 bytes)
	// Contains the fragment and sequence numbers for the frame.
	SequenceControl uint16

	// Information Elements (IEs) - Variable length.
	// This is where most of the specific probe request data resides.
	InformationElements []InformationElement
}

// InformationElement represents an 802.11 Information Element.
type InformationElement struct {
	ID          uint8  // Element ID
	Length      uint8  // Length of the Information field (variable length)
	Info        []byte // The actual information content
	IDExtension *uint8 // Optional Element ID Extension for some elements
}

// Example of Information Element IDs (partial list)
const (
	ElementIDSSID                   uint8 = 0 // Service Set Identifier
	ElementIDSupportedRates         uint8 = 1 // Supported Rates
	ElementIDFHParameterSet         uint8 = 2
	ElementIDDSParameterSet         uint8 = 3 // DS Parameter Set
	ElementIDCFParameterSet         uint8 = 4
	ElementIDTIM                    uint8 = 5
	ElementIDIBSSParameterSet       uint8 = 6
	ElementIDCountry                uint8 = 7
	ElementIDHoppingPattern         uint8 = 8
	ElementIDHoppingPatternTable    uint8 = 9
	ElementIDRequest                uint8 = 10
	ElementIDChallengeText          uint8 = 16
	ElementIDPowerConstraint        uint8 = 32
	ElementIDChannelSwitch          uint8 = 37
	ElementIDERP                    uint8 = 42  // ERP Information
	ElementIDExtendedSupportedRates uint8 = 50  // Extended Supported Rates
	ElementIDHTCapabilities         uint8 = 45  // HT Capabilities
	ElementIDHTInformation          uint8 = 61  // HT Information
	ElementIDVHTCapabilities        uint8 = 191 // VHT Capabilities
	ElementIDVendorSpecific         uint8 = 221 // Vendor Specific Information
)

// ParseProbeRequest takes raw byte data and attempts to parse it into a ProbeRequest struct.
// This is a simplified example and would need robust error handling and more complex parsing
// for a production-level implementation.
func ParseProbeRequest(data []byte) (*ProbeRequest, error) {
	if len(data) < 24 { // Minimum size for an 802.11 MAC header
		return nil, fmt.Errorf("probe request data too short")
	}

	probeReq := &ProbeRequest{}

	// Skip Frame Control and Duration/ID field for simplicity, assuming they are parsed elsewhere
	// For actual parsing, you'd need to extract these fields correctly.

	// Destination Address (bytes 4-9 in 802.11 MAC header)
	probeReq.DestinationAddress = net.HardwareAddr(data[4:10])

	// Source Address (bytes 10-15 in 802.11 MAC header)
	probeReq.SourceAddress = net.HardwareAddr(data[10:16])

	// BSSID (bytes 16-21 in 802.11 MAC header)
	probeReq.BSSID = net.HardwareAddr(data[16:22])

	// Sequence Control (bytes 22-23 in 802.11 MAC header)
	probeReq.SequenceControl = binary.LittleEndian.Uint16(data[22:24])

	// Information Elements (start after the MAC header)
	// This is a simplified parsing. In reality, you'd iterate through IEs
	// based on Element ID and Length fields.

	// Parse Information Elements (IEs) starting at offset 24
	ieData := data[24:]
	for len(ieData) >= 2 {
		id := ieData[0]
		length := ieData[1]
		if len(ieData) < int(length)+2 {
			return nil, fmt.Errorf("malformed information element, info field incomplete")
		}
		ie := InformationElement{
			ID:     id,
			Length: length,
			Info:   ieData[2 : 2+length],
		}
		probeReq.InformationElements = append(probeReq.InformationElements, ie)
		ieData = ieData[2+length:]
	}

	return probeReq, nil
}

func (probeReq *ProbeRequest) String() string {
	// Example of a raw Probe Request frame (simplified and illustrative)
	// In a real scenario, this would come from a packet capture.
	// This example assumes a basic structure, including:
	// - Frame Control (2 bytes - type/subtype, etc.)
	// - Duration (2 bytes)
	// - Destination Address (6 bytes - typically broadcast for probe requests)
	// - Source Address (6 bytes)
	// - BSSID (6 bytes - typically broadcast for probe requests)
	// - Sequence Control (2 bytes)
	// - Information Elements (variable length)
	//   - SSID (Element ID 0)
	//   - Supported Rates (Element ID 1)

	var pr string
	pr += "Probe Request:\n"
	pr += fmt.Sprintf("  Destination Address: %s\n", probeReq.DestinationAddress)
	pr += fmt.Sprintf("  Source Address:      %s\n", probeReq.SourceAddress)
	pr += fmt.Sprintf("  BSSID:             %s\n", probeReq.BSSID)
	pr += fmt.Sprintf("  Sequence Control:  %d\n", probeReq.SequenceControl)
	pr += "  Information Elements:\n"
	for _, ie := range probeReq.InformationElements {
		pr += fmt.Sprintf("    ID: %d, Length: %d, Info: %x", ie.ID, ie.Length, ie.Info)
		if ie.ID == ElementIDSSID {
			pr += fmt.Sprintf(" (SSID: %s)", ie.Info) // Interpret SSID as string
		}
	}
	return pr
}

func (m ProbeRequest) LayerType() gopacket.LayerType { return L80211Layer }
func (m ProbeRequest) LayerContents() []byte         { return []byte(m.String()) }
func (m ProbeRequest) LayerPayload() []byte          { return nil }
func (m ProbeRequest) CanDecode() gopacket.LayerClass {
	return L80211Layer
}

func ParseProbeReq(pr []byte) (*ProbeRequest, error) {
	if len(pr) < 24 { // Minimum size for an 802.11 MAC header
		return nil, fmt.Errorf("probe request data too short")
	}

	// Parse the Probe Request frame
	probeReq, err := ParseProbeRequest(pr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse probe request: %w", err)
	}

	return probeReq, nil
}
