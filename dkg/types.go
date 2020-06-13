package dkg

import (
	pb "github.com/sourcenetwork/secrets-poc/dkg/pb"

	dkgp "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v3/share/vss/pedersen"
	"google.golang.org/protobuf/proto"
)

type DealPacket struct {
	Deal *dkgp.Deal
}

// Read a serialized proto.DKGResponse message, return a ResponsePacket
func (dp DealPacket) Read(buf []byte) (DealPacket, error) {
	deal := &pb.DKGDeal{}
	if err := proto.Unmarshal(buf, deal); err != nil {
		return DealPacket{}, err
	}
	return DealPacket{
		Deal: &dkgp.Deal{
			Index: deal.Index,
			Deal: &vss.EncryptedDeal{
				DHKey:     deal.IssuedDeal.DHKey,
				Signature: deal.IssuedDeal.Signature,
				Nonce:     deal.IssuedDeal.Nonce,
				Cipher:    deal.IssuedDeal.Cipher,
			},
			Signature: deal.Signature,
		},
	}, nil
}

// Write a ResponsePacket into a serialized proto.DKGResponse message
func (dp DealPacket) Write() ([]byte, error) {
	deal := &pb.DKGDeal{
		Index: dp.Deal.Index,
		IssuedDeal: &pb.IssuedDeal{
			DHKey:     dp.Deal.Deal.DHKey,
			Signature: dp.Deal.Deal.Signature,
			Nonce:     dp.Deal.Deal.Nonce,
			Cipher:    dp.Deal.Deal.Cipher,
		},
		Signature: dp.Deal.Signature,
	}
	return proto.Marshal(deal)
}

type ResponsePacket struct {
	Response *dkgp.Response
}

// Read a serialized proto.DKGResponse message, return a ResponsePacket
func (rp ResponsePacket) Read(buf []byte) (ResponsePacket, error) {
	resp := &pb.DKGResponse{}
	if err := proto.Unmarshal(buf, resp); err != nil {
		return ResponsePacket{}, err
	}
	return ResponsePacket{
		Response: &dkgp.Response{
			Index: resp.Index,
			Response: &vss.Response{
				SessionID: resp.IssuedResponse.SessionID,
				Index:     resp.IssuedResponse.Index,
				Status:    resp.IssuedResponse.Status,
				Signature: resp.IssuedResponse.Signature,
			},
		},
	}, nil
}

// Write a ResponsePacket into a serialized proto.DKGResponse message
func (rp ResponsePacket) Write() ([]byte, error) {
	resp := &pb.DKGResponse{
		Index: rp.Response.Index,
		IssuedResponse: &pb.IssuedResponse{
			SessionID: rp.Response.Response.SessionID,
			Index:     rp.Response.Response.Index,
			Status:    rp.Response.Response.Status,
			Signature: rp.Response.Response.Signature,
		},
	}
	return proto.Marshal(resp)
}
