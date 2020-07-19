package dkg

import (
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-msgio"
	pb "github.com/sourcenetwork/secrets-poc/dkg/pb"
	dkgp "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"google.golang.org/protobuf/proto"
)

/*

Async DKG coordination
Goal: Initiate a DKG generation with peers as they join over time. Async vs Sync

handleStream()
- New stream open between two peers
- New DKG instance, initialize DKG state
- start loop with peer
-

*/

// handles protocol: /secrets/dkg/0.1.0
func (dkg *DKG) ProtocolHandler(stream network.Stream) {
	// is this peer in our dkg.peerset
	// - yes: initiate new peer state
	// - no: close
	c := stream.Conn()
	peerID := c.RemotePeer()
	// pubkey := c.RemotePublicKey()

	dkg.HandlePeerStream(peerID, stream)
}

func (dkg *DKG) HandlePeerStream(peerID peer.ID, stream network.Stream) {
	if !dkg.inPeerset(peerID) {
		stream.Close()
		return
	}

	sub, err := dkg.respBus.Subscribe(new(ResponsePacket))
	if err != nil {
		panic(err)
	}
	n := &node{
		id:      peerID,
		stream:  stream,
		reader:  msgio.NewReader(stream),
		writer:  msgio.NewWriter(stream),
		respSub: sub,
	}

	dkg.startPeerLoop(n)
}

func (dkg *DKG) startRootLoop() {
	// save all emitted responses to a list
	timer := time.Tick(time.Second * 1)
	select {
	case resp := <-dkg.respSub.Out():
		dkg.respBufferLock.Lock()
		r := resp.(*dkgp.Response)
		dkg.responses[r.Index] = r
		dkg.respBufferLock.Unlock()
	case <-timer:
		if dkg.dkg.Certified() {
			fmt.Println("DKG is initialized")
			return // dkg is finished
		}
	}
}

func (dkg *DKG) startPeerLoop(peer *node) {
	// check for outstanding deal intended for this node
	index := dkg.peerIndex(peer.id)
	deal, exists := dkg.deals[index]
	if exists { // deliver
		packet := DealPacket{deal}
		err := peer.Send(packet)
		if err != nil {
			panic(err)
		}
	}

	go func() {
		// send outstanding responses
		dkg.respBufferLock.Lock()
		for _, resp := range dkg.responses {
			packet := ResponsePacket{resp}
			err := peer.Send(packet)
			if err != nil {
				panic(err)
			}
		}
		dkg.respBufferLock.Unlock()
		// send all future emitted responses
		for resp := range peer.respSub.Out() {
			packet := ResponsePacket{resp.(*dkgp.Response)}
			err := peer.Send(packet)
			if err != nil {
				panic(err)
			}
		}
	}()

	for {
		b, err := peer.reader.ReadMsg()
		if err != nil {
			peer.stream.Close()
			return
		}

		var msg proto.Message
		err = proto.Unmarshal(b, msg)
		if err != nil {
			peer.stream.Close()
			return
		}

		switch packet := msg.(type) {
		case *pb.DKGDeal:
			dkg.handleDealPacket(peer, packet)
		case *pb.DKGResponse:
			dkg.handleResponsePacket(peer, packet)
		}
	}
}

func (dkg *DKG) handleDealPacket(peer *node, msg *pb.DKGDeal) error {
	deal := DealPacket{}.FromProto(msg)
	err := dkg.HandleDeal(deal.Deal)
	if err != nil {
		panic(err)
	}
	return nil
}

func (dkg *DKG) handleResponsePacket(peer *node, msg *pb.DKGResponse) error {
	resp := ResponsePacket{}.FromProto(msg)
	err := dkg.ProcessResponse(resp.Response)
	if err != nil {
		panic(err)
	}
	return nil
}

func (dkg *DKG) Start() error {
	go dkg.startRootLoop()
	return dkg.GenerateDeals()
}
