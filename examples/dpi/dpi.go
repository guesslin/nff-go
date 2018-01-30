package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Sample input pcap files can be downloaded from http://wiresharkbook.com/studyguide.html
// Test samples:
// http-cnn2012.pcapng
// http-facebook.pcapng
// http-downloadvideo.pcapng
// google-http.pcapng
//
// Note: only pcap format is supported. Convert pcapng to pcap:
// editcap -F pcap http-facebook.pcapng http-facebook.pcap
//
// Rules read from JSON. Rules in file should go in increasing priority.
// Each next rule is more specific and refines (or overwrites) result
// of previous rules check

const (
	// Last flow among totalNumFlows is for dropped packets
	totalNumFlows uint = 5
	numFlows      uint = totalNumFlows - 1
)

var (
	// Number of allowed packets for each flow
	allowedPktsCount [numFlows]uint64
	// Number of read packets for each flow
	readPktsCount [numFlows]uint64
	// Number of packets blocked by signature for each flow
	blockedPktsCount [numFlows]uint64

	rules []rule
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	infile := flag.String("infile", "", "input pcap file")
	outfile := flag.String("outfile", "allowed_packets.pcap", "output pcap file with allowed packets")
	rulesfile := flag.String("rfile", "test-rules.json", "input json file, specifying rules")
	nreads := flag.Int("nreads", 1, "number pcap file reads")
	timeout := flag.Duration("timeout", 10*time.Second, "time to run in seconds")
	//useHyperscan := flag.Bool("hs", false, "use Intel Hyperscan library for regex match")
	flag.Parse()

	// Initialize NFF-Go library
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	var err error
	rules, err = getRulesFromFile(*rulesfile)
	CheckFatal(err)

	// Receive packets from given PCAP file
	inputFlow := flow.SetReceiverFile(*infile, int32(*nreads))

	// Split packets into flows by hash of five-tuple
	// Packets without five-tuple are put in last flow and will be dropped
	outputFlows, err := flow.SetSplitter(inputFlow, splitBy5Tuple, totalNumFlows, nil)
	CheckFatal(err)

	// Drop last flow
	CheckFatal(flow.SetStopper(outputFlows[totalNumFlows-1]))

	for i := uint(0); i < numFlows; i++ {
		lc := localCounters{handlerId: i}
		CheckFatal(flow.SetHandlerDrop(outputFlows[i], filterPackets, lc))
	}

	outFlow, err := flow.SetMerger(outputFlows[:numFlows]...)
	CheckFatal(err)

	CheckFatal(flow.SetSenderFile(outFlow, *outfile))

	go func() {
		CheckFatal(flow.SystemStart())
	}()

	// Finish by timeout, as cannot verify if file reading finished
	time.Sleep(*timeout)

	// Compose info about all handlers
	var read uint64
	var allowed uint64
	var blocked uint64
	fmt.Println("\nHandler statistics")
	for i := uint(0); i < numFlows; i++ {
		fmt.Printf("Handler %d processed %d packets (allowed=%d, blocked by signature=%d)\n",
			i, readPktsCount[i], allowedPktsCount[i], blockedPktsCount[i])
		read += readPktsCount[i]
		allowed += allowedPktsCount[i]
		blocked += blockedPktsCount[i]
	}
	fmt.Println("Total:")
	fmt.Println("read =", read)
	fmt.Println("allowed =", allowed)
	fmt.Println("blocked =", blocked)
	fmt.Println("dropped (read - allowed) =", read-allowed)
}

type localCounters struct {
	handlerId         uint
	allowedCounterPtr *uint64
	readCounterPtr    *uint64
	blockedCounterPtr *uint64
}

// Create new counters for new handler
func (lc localCounters) Copy() interface{} {
	var newlc localCounters
	// Clones has the same id
	id := lc.handlerId
	newlc.handlerId = id
	newlc.allowedCounterPtr = &allowedPktsCount[id]
	newlc.readCounterPtr = &readPktsCount[id]
	newlc.blockedCounterPtr = &blockedPktsCount[id]
	return newlc
}

func (lc localCounters) Delete() {
}

func filterPackets(pkt *packet.Packet, context flow.UserContext) bool {
	cnt := context.(localCounters)
	numRead := cnt.readCounterPtr
	numAllowed := cnt.allowedCounterPtr
	numBlocked := cnt.blockedCounterPtr

	atomic.AddUint64(numRead, 1)
	data := extractData(pkt)
	accept := false

	for _, rule := range rules {
		result := rule.Re.Match(data)
		if !result {
			continue
		}
		if rule.Allow {
			accept = true
		} else {
			accept = false
			atomic.AddUint64(numBlocked, 1)
		}
	}
	if accept {
		atomic.AddUint64(numAllowed, 1)
	}
	return accept
}

func splitBy5Tuple(pkt *packet.Packet, context flow.UserContext) uint {
	h := fnv.New64a()
	ip4, ip6, _ := pkt.ParseAllKnownL3()
	if ip4 != nil {
		pkt.ParseL4ForIPv4()
	} else if ip6 != nil {
		pkt.ParseL4ForIPv6()
	} else {
		// Other protocols not supported
		return totalNumFlows - 1
	}

	if ip4 != nil {
		binary.Write(h, binary.BigEndian, ip4.NextProtoID)
		buf := new(bytes.Buffer)
		CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.SrcAddr))
		h.Write(buf.Bytes())
		CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.DstAddr))
		h.Write(buf.Bytes())
	} else if ip6 != nil {
		binary.Write(h, binary.BigEndian, ip6.Proto)
		h.Write(ip6.SrcAddr[:])
		h.Write(ip6.DstAddr[:])
	}
	binary.Write(h, binary.BigEndian, pkt.GetTCPNoCheck().SrcPort)
	binary.Write(h, binary.BigEndian, pkt.GetTCPNoCheck().DstPort)

	hash := uint(h.Sum64())
	return hash % numFlows
}

func extractData(pkt *packet.Packet) []byte {
	pktLen := pkt.GetPacketSegmentLen()
	pktStartAddr := pkt.StartAtOffset(0)
	pktBytes := (*[1 << 30]byte)(pktStartAddr)[:pktLen]
	pkt.ParseData()

	hdrsLen := uintptr(pkt.Data) - uintptr(pktStartAddr)
	return pktBytes[hdrsLen:]
}

func getRulesFromFile(filename string) ([]rule, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	rules = make([]rule, 0)
	if err := json.Unmarshal(f, &rules); err != nil {
		return nil, err
	}
	for i := 0; i < len(rules); i++ {
		rules[i].Re = regexp.MustCompile(rules[i].Regexp)
	}
	return rules, nil
}

type rule struct {
	Name   string
	Regexp string
	Re     *regexp.Regexp
	Allow  bool
}
