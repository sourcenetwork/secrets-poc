package dkg

import (
	"errors"
	"sync"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	dkgp "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/libp2p/go-eventbus"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/event"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-msgio"
	// "google.golang.org/protobuf/proto"
)

type node struct {
	id      peer.ID
	stream  network.Stream
	reader  msgio.Reader
	writer  msgio.Writer
	respSub event.Subscription
}

func (n *node) Send(msg packet) error {
	b, err := msg.Bytes()
	if err != nil {
		return err
	}
	return n.writer.WriteMsg(b)
}

type DKG struct {
	dkg      *dkgp.DistKeyGenerator
	suite    suites.Suite
	nodes    []*node
	points   []kyber.Point
	numNodes int

	threshold int

	initialized bool
	publicShare kyber.Point

	deals map[int]*dkgp.Deal

	responses      []*dkgp.Response
	respBufferLock *sync.Mutex
	respBus        event.Bus
	respEmitter    event.Emitter
	respSub        event.Subscription
}

func publicKeyToEdwards25519KyberPoint(pubkey []byte) kyber.Point {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	point := suite.Point()
	point.UnmarshalBinary(pubkey)
	return point
}

func privateKeyToEdwards25519KyberPoint(priv []byte) kyber.Scalar {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	scalar := suite.Scalar()
	scalar.UnmarshalBinary(priv)
	return scalar
}

func NewDKG(privateKey crypto.PrivKey, peers []peer.ID, threshold int) (*DKG, error) {
	// dkg := &DKG{}
	respBus := eventbus.NewBus()
	respEmitter, err := respBus.Emitter(new(ResponsePacket))
	if err != nil {
		return nil, err
	}
	respSub, err := respBus.Subscribe(new(ResponsePacket), eventbus.BufSize(len(peers)))
	if err != nil {
		return nil, err
	}

	// build peer kyber points
	points := make([]kyber.Point, len(peers))
	for i, pid := range peers {
		pubkey, err := pid.ExtractPublicKey()
		if err != nil {
			return nil, err
		}
		pubBytes, err := pubkey.Raw()
		if err != nil {
			return nil, err
		}
		points[i] = publicKeyToEdwards25519KyberPoint(pubBytes)
	}

	// priv key to Kyber Scalar
	privBytes, err := privateKey.Raw()
	if err != nil {
		return nil, err
	}
	scalar := privateKeyToEdwards25519KyberPoint(privBytes)

	// build EC suite and pederson DKG
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tdkg, err := dkgp.NewDistKeyGenerator(suite, scalar, points, threshold)
	if err != nil {
		return nil, err
	}

	return &DKG{
		dkg:         tdkg,
		suite:       suite,
		points:      points,
		numNodes:    len(peers),
		responses:   make([]*dkgp.Response, len(peers)),
		threshold:   threshold,
		initialized: false,
		respBus:     respBus,
		respEmitter: respEmitter,
		respSub:     respSub,
	}, nil
}

func (dkg DKG) inPeerset(p peer.ID) bool {
	for _, peer := range dkg.nodes {
		if string(p) == string(peer.id) {
			return true
		}
	}
	return false
}

func (dkg DKG) peerIndex(p peer.ID) int {
	for i, peer := range dkg.nodes {
		if string(p) == string(peer.id) {
			return i
		}
	}
	return -1
}

func (d *DKG) Certified() bool {
	return d.dkg.Certified()
}

func (d *DKG) Public() kyber.Point {
	if d.Certified() {
		distKey, err := d.dkg.DistKeyShare()
		if err != nil {
			panic(err)
		}
		return distKey.Public()
	}

	return nil
}

// Generate Deals
func (d *DKG) GenerateDeals() error {
	// generate all the deals for all the intended nodes
	deals, err := d.dkg.Deals() // omits deal for ourself
	if err != nil {
		return err
	}
	// log.Info().Msg("Generated deals, exchanging...")
	d.deals = deals

	return nil
}

func (d *DKG) HandleDeal(deal *dkgp.Deal) error {
	// // fmt.Println("-------------------------------------")
	// for _, v := range d.dkg.Verifiers() {
	// 	fmt.Println(v.Responses())
	// }
	// // fmt.Println("-------------------------------------")
	resp, err := d.dkg.ProcessDeal(deal)
	if err != nil {
		return err
	}
	// broadcast resp to all nodes
	d.responses[resp.Index] = resp
	respPacket := &ResponsePacket{Response: resp}
	d.respEmitter.Emit(respPacket)

	// log.Info().Msg("Broadcasting deal response to all peers")
	// for _, peer := range d.nodes {
	// 	if peer.node != nil {
	// 		log.Info().Msgf("Broadcasting response to %v", peer.PublicKey)
	// 		err = peer.node.SendMessage(respPacket)
	// 		if err != nil {
	// 			return err
	// 		}
	// 	}
	// }
	// err = d.ProcessResponse(resp)
	return nil
}

func (d *DKG) ProcessResponse(resp *dkgp.Response) error {
	justification, err := d.dkg.ProcessResponse(resp)
	if err != nil {
		return err
	}
	if justification != nil {
		return errors.New("there should be no justification")
	}
	return nil
}
