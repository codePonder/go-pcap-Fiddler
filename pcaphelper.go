//pcaphelper package implements parsing of the pcap file format, for UDP datagrams
package pcaphelper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

// define states for the pcap parser.  Make specific type to make
// sure the states are only used as ...  states
type processPcapParseState uint

const (
	checkMagicNumber processPcapParseState = iota
	getPcapPacket
	getEthernetHeader
	get_IPV4_UDP_Header
	allDone
)

const magicNumber = 0xa1b2c3d4
const ipv4_isUDP = 17
const maxDataGram = 7 * 188

//const ipv4_isTCP = 6
const pcapFileHeaderLength = 24
const pcapPacketHeaderLength = 16
const ethernetHeaderLength = 14
const ipv4HeaderLength = 20
const udpHeaderLength = 8
const minDataLength = pcapPacketHeaderLength + ethernetHeaderLength + ipv4HeaderLength + udpHeaderLength

// ipV4HeaderFormat defines the bitfields that are found in the IP header (IPv4)
type ipV4HeaderFormat struct {
	version           uint
	headerLength      uint
	dccp              uint
	ecn               uint
	totalLength       uint
	id                uint
	flags             uint
	fragmentOffset    uint
	ttl               uint
	protocol          uint
	checkSum          uint
	sourceIPAddr      string
	destinationIPAddr string
}

type udpHeaderFormat struct {
	sourcePort      uint16
	destinationPort uint16
	length          uint16
	checkSum        uint16
}

// below type encapsulates all the information required for a
// parsing of pcaps
type pcapParsingContext struct {
	inputFilename       string
	outputFilename      string
	multicastsFound     map[string]uint
	dataGramsPresent    int
	inputFileHandle     *os.File
	tsOutFileHandle     *os.File
	lastPosition        int64
	beVerbose           bool
	showResults         bool
	nonIPPayloadPacket  uint64
	inputFileLeft       int64
	startNextPcapPacket int64
	storePayloadsToFile bool
	addressToStore      string
	dataBufferXfer      [maxDataGram]byte
}

// list of modes that are implremented, used to check that the
// asked for operation is possible
var validModes = [...]string{"list-pcap-multicasts"}

// check that the mode is currently supported
func testModeIsSupported(modeRequested string) error {
	for _, modeSupported := range validModes {
		if modeRequested == modeSupported {
			return nil
		}
	}
	return errors.New("mode requested not found")
}

// check that the magic codeword is present in the file.
// if it isn't, this is not a pcap file and we should
// abandon things here and let the user know
func isThisAPCapFile(info *pcapParsingContext) error {

	//error err
	pcapHeaderdata := make([]byte, pcapFileHeaderLength)
	_, err := info.inputFileHandle.Read(pcapHeaderdata)

	if err != nil {
		log.Fatal(err)
	}

	headerMagicNumber := binary.LittleEndian.Uint32(pcapHeaderdata[0:4])
	if headerMagicNumber == magicNumber {
		versionMajor := binary.LittleEndian.Uint16(pcapHeaderdata[4:6])
		versionMinor := binary.LittleEndian.Uint16(pcapHeaderdata[6:8])
		timeZone := binary.LittleEndian.Uint32(pcapHeaderdata[8:12])
		sigFigs := binary.LittleEndian.Uint32(pcapHeaderdata[12:16])
		snapLen := binary.LittleEndian.Uint32(pcapHeaderdata[16:20])
		network := binary.LittleEndian.Uint32(pcapHeaderdata[20:24])

		if info.beVerbose {
			fmt.Printf(" magicNumber %x \n", headerMagicNumber)
			fmt.Printf(" major %x   minor %x \n", versionMajor, versionMinor)
			fmt.Printf(" timeZone  %x   sigFigs %x   snaplen %x    network %x \n", timeZone, sigFigs, snapLen, network)
		}
		info.startNextPcapPacket, err = info.inputFileHandle.Seek(0, 1)
		return err
	} else {
		// read first bytes from file - they should contain
		return errors.New(" !! This is not a pcap file !!   ")
	}
}

// parseudpHeader reads and interprets UDP headers
func parseudpHeader(info *pcapParsingContext) (destPort uint16, payloadLength uint16, err error) {

	var udpInfo udpHeaderFormat
	dataBuffer := make([]byte, udpHeaderLength)
	_, err = info.inputFileHandle.Read(dataBuffer)

	if err != nil {
		err = errors.New(" oops during usp header parsing")
		return
	}

	udpInfo.sourcePort = binary.BigEndian.Uint16(dataBuffer[0:2])
	udpInfo.destinationPort = binary.BigEndian.Uint16(dataBuffer[2:4])
	udpInfo.length = binary.BigEndian.Uint16(dataBuffer[4:6])
	udpInfo.checkSum = binary.BigEndian.Uint16(dataBuffer[6:8])

	if info.beVerbose {
		fmt.Printf(" ====== UDP Header ========\n")
		fmt.Printf(" Src Port %d  destination Port %d \n", udpInfo.sourcePort, udpInfo.destinationPort)
		fmt.Printf(" Length  %d  checkSum 0x%04x \n", udpInfo.length, udpInfo.checkSum)
	}
	destPort = udpInfo.destinationPort

	info.dataGramsPresent++
	payloadLength = udpInfo.length - 8

	return
}

// readIPv4Header reads the IPv4 header from file.  This header contains the source and destination IP addresses
// and the format flag to indicate if we have a UDP packets laying beneath this
// 20 bytes long
func read_IPv4_UDP_Headers(info *pcapParsingContext) error {

	var ipv4Info ipV4HeaderFormat
	ipv4HeaderData := make([]byte, ipv4HeaderLength)
	_, err := info.inputFileHandle.Read(ipv4HeaderData)

	if err != nil {
		if err == io.EOF {
			return err
		}
		return errors.New(" problem encountered reading IP header ")
	}

	ipv4Info.version = uint(ipv4HeaderData[0]) >> 4
	ipv4Info.headerLength = uint(ipv4HeaderData[0]) & 0xf
	ipv4Info.dccp = uint(ipv4HeaderData[1]) >> 2
	ipv4Info.ecn = uint(ipv4HeaderData[1]) & 0x3
	ipv4Info.totalLength = uint(ipv4HeaderData[2])<<8 + uint(ipv4HeaderData[3])
	ipv4Info.id = uint(ipv4HeaderData[4])<<8 + uint(ipv4HeaderData[5])
	ipv4Info.flags = uint(ipv4HeaderData[6]) & 0x7
	ipv4Info.fragmentOffset = ((uint(ipv4HeaderData[6]) & 0xf8) << 5) + uint(ipv4HeaderData[7])

	ipv4Info.ttl = uint(ipv4HeaderData[8])
	ipv4Info.protocol = uint(ipv4HeaderData[9])
	ipv4Info.checkSum = (uint(ipv4HeaderData[10]) << 8) + uint(ipv4HeaderData[11])

	ipv4Info.sourceIPAddr = fmt.Sprintf("%d.%d.%d.%d", ipv4HeaderData[12], ipv4HeaderData[13], ipv4HeaderData[14], ipv4HeaderData[15])
	ipv4Info.destinationIPAddr = fmt.Sprintf("%d.%d.%d.%d", ipv4HeaderData[16], ipv4HeaderData[17], ipv4HeaderData[18], ipv4HeaderData[19])

	var isUDP bool
	var destinationMulticast string
	if ipv4Info.protocol == ipv4_isUDP {
		isUDP = true
		// if its UDP then parse the UDP header to get the port sectoipn of the address
		destinationPort, payloadLength, err := parseudpHeader(info)
		if err != nil {
			return errors.New(" problem encountered reading UDP header ")
		}

		destinationMulticast = ipv4Info.destinationIPAddr + fmt.Sprintf(":%d", destinationPort)
		if (info.storePayloadsToFile) && (info.addressToStore == destinationMulticast) {
			if payloadLength > maxDataGram {
				return errors.New("UDP Payload > 7 x 188 Bytes, too much data")
			}
			if payloadLength%188 != 0 {
				return errors.New("UDP Payload not multiple of TS Packets")
			}
			tempDataBuffer := info.dataBufferXfer[:payloadLength]
			_, payloadReadError := info.inputFileHandle.Read(tempDataBuffer)
			if payloadReadError != nil {
				return errors.New(" problem encountered reading UDP payload ")
			}
			info.tsOutFileHandle.Write(tempDataBuffer)
		}

		if info.beVerbose {
			fmt.Printf("\n ========= IP/UDP headers  ========= \n")
			fmt.Printf("  Pkt Length %d (includes 8 bytes for udp header)\n", ipv4Info.totalLength)
			fmt.Printf("  Protocol 0x%x   .. is UDP %v \n", ipv4Info.protocol, isUDP)
			fmt.Printf("  checkSum 0x%x \n", ipv4Info.checkSum)
			fmt.Printf("  source  %s   --> destination %s   \n \n", ipv4Info.sourceIPAddr, destinationMulticast)
		}
	} else {
		isUDP = false
	}

	info.multicastsFound[destinationMulticast] += 1

	return err
}

// reads the ethenet header and checks that is in fact an ethernt header
// if header is not as expected, raise error, else return nil to carry on....
// ethernet header is assumed tobe an ethernet II frame so..
//  Dest_Mac (6 bytes)  Source Mac (6 bytes)  Type (2 Bytes)  For this - type must
// be 0x800 for IP Payload
func readEthernetHeader(info *pcapParsingContext) error {

	// first latch the position of the file reader
	var err error
	info.lastPosition, err = info.inputFileHandle.Seek(0, 1)

	ethernetHeader := make([]byte, ethernetHeaderLength)
	_, err = info.inputFileHandle.Read(ethernetHeader)

	if err != nil {
		log.Fatal(err)
	}

	if info.beVerbose {
		destMAC := fmt.Sprintf("%02x::%02x::%02x::%02x::%02x::%02x", ethernetHeader[0], ethernetHeader[1], ethernetHeader[2],
			ethernetHeader[3], ethernetHeader[4], ethernetHeader[5])
		sourceMAC := fmt.Sprintf("%02x::%02x::%02x::%02x::%02x::%02x", ethernetHeader[6], ethernetHeader[7], ethernetHeader[8],
			ethernetHeader[9], ethernetHeader[10], ethernetHeader[11])
		fmt.Printf("source MAC %s \n", sourceMAC)
		fmt.Printf("dest MAC %s \n", destMAC)
	}
	var payloadType uint16 = binary.BigEndian.Uint16(ethernetHeader[12:14])

	if payloadType != 0x800 {
		info.nonIPPayloadPacket += 1
	}

	return nil
}

// every packet has a pcap packet header appended to it.  Format from wirwshark wiki is
// typedef struct pcaprec_hdr_s {
// 	guint32 ts_sec;         /* timestamp seconds */
// 	guint32 ts_usec;        /* timestamp microseconds */
// 	guint32 incl_len;       /* number of octets of packet saved in file */
// 	guint32 orig_len;       /* actual length of packet */
// } pcaprec_hdr_t;
// Read as 16 bytes, then binary encode into above structures
// incl_len is the length of the pcap packet, NOT including the header
// so - read 16 bytes, file pointer is pointing just after the header
// add incl_len to current file pos and you'll be pointing at the start of the
// next pcap packet header.   To give us resilience -
// always store startOfNextPcapPacket so that when we come around again... we can
// jump to a point that we should know is OK
// also - by setting the pointer to the start of teh next pcap Chunk, if it runs off the end
// of the file we know that before we try to parse any more data.  Only complete packets will
// pass beyond this point

func readPacketHeader(info *pcapParsingContext) (dataConsumed int64, err error) {
	pcapHeaderdata := make([]byte, pcapPacketHeaderLength)

	dataConsumed = 0
	// point to the start of the next header
	_, err = info.inputFileHandle.Seek(info.startNextPcapPacket, 0)
	if err != nil {
		return
	}
	_, err = info.inputFileHandle.Read(pcapHeaderdata)

	if err != nil {
		return
	}
	parser := binary.LittleEndian.Uint32
	timeSecsP := parser(pcapHeaderdata[0:4])
	timeSecs := binary.LittleEndian.Uint32(pcapHeaderdata[0:4])
	timeuSecs := binary.LittleEndian.Uint32(pcapHeaderdata[4:8])
	lengthInFile := binary.LittleEndian.Uint32(pcapHeaderdata[8:12])
	lengthOfPacket := binary.LittleEndian.Uint32(pcapHeaderdata[12:16])

	if info.beVerbose {
		fmt.Printf(" time %d   %d  :: %d \n", timeSecs, timeSecsP, timeuSecs)
		fmt.Printf(" length   In File  %d   of Packet  %d \n", lengthInFile, lengthOfPacket)
	}

	// latch the start of the next header, the idea is that at the start of this function
	// we jump to startNextPcapPacket  then process from there.  It means we can jump
	// payloads, also if we get "lost" we should return as we know he pcap packet lengths
	// so can always find the next pcap packet header.
	dataConsumed = int64(lengthInFile + pcapPacketHeaderLength)
	info.startNextPcapPacket += int64(dataConsumed)
	return
}

// if you want to see what was found, below function will print out.
func displayResults(info *pcapParsingContext) (err error) {
	err = nil

	fmt.Println(" ========================================= ")
	fmt.Printf(" File %s processed \n", info.inputFilename)
	fmt.Printf(" multicasts found address : number Datagrams \n")
	for key := range info.multicastsFound {
		fmt.Printf(" %s : %d \n", key, info.multicastsFound[key])
	}
	fmt.Printf(" total Datagrams processed %d \n", info.dataGramsPresent)
	fmt.Printf(" non IP data payloads %d \n", info.nonIPPayloadPacket)
	fmt.Println(" ========================================= ")

	return
}

// entryPoint
func Pcaphelper() error {

	var err error
	var dataUsed int64
	mode := "list-pcap-multicasts"
	validMode := testModeIsSupported(mode)

	var info pcapParsingContext
	info.beVerbose = false
	info.showResults = true
	info.storePayloadsToFile = true
	info.addressToStore = "239.114.25.1:5000"

	if info.multicastsFound == nil {
		info.multicastsFound = make(map[string]uint)
	}

	if validMode != nil {
		return errors.New("pcaphelper does not support the requested mode")
	}

	//Gets the file info structure for the target file
	info.inputFilename = "/home/chris/tsutils/Fox.pcap"
	info.outputFilename = "/home/chris/tsutils/extractTest.ts"
	stats, err := os.Stat(info.inputFilename)
	if err != nil {
		fmt.Println(" getting the file stats failed - check the file is real ")
		os.Exit(1)
	}
	info.inputFileLeft = stats.Size()

	info.inputFileHandle, err = os.Open(info.inputFilename)
	if err != nil {
		log.Fatal("Error while opening input file", err)
	}
	defer info.inputFileHandle.Close()

	info.tsOutFileHandle, err = os.Create(info.outputFilename)
	if err != nil {
		log.Fatal("Error while opening output file", err)
	}
	defer info.tsOutFileHandle.Close()

	fmt.Printf(" opened %s \n", info.inputFilename)

	err = isThisAPCapFile(&info)
	processState := getPcapPacket

	for processState != allDone {
		if err == nil && processState != allDone {
			switch processState {
			case getPcapPacket:
				dataUsed, err = readPacketHeader(&info)
				info.inputFileLeft -= dataUsed
				if info.inputFileLeft < minDataLength {
					processState = allDone
				} else {
					processState = getEthernetHeader
				}
			case getEthernetHeader:
				err = readEthernetHeader(&info)
				processState = get_IPV4_UDP_Header
			case get_IPV4_UDP_Header:
				err = read_IPv4_UDP_Headers(&info)
				processState = getPcapPacket
			default:
				fmt.Println(" !! unknown state encountered !! ")
			}
		} else {
			processState = allDone
			break
		}
	}

	if err != nil {
		if err == io.EOF {
			fmt.Printf(" === Found end of file  with data left level %v === \n", info.inputFileLeft)
		} else {
			log.Fatal(err)
		}
	}

	if info.showResults {
		displayResults(&info)
	}

	return err
}
