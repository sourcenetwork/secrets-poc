// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.11.2
// source: messages.proto

package pb

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type DexPacket struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Deal *DKGDeal `protobuf:"bytes,1,opt,name=deal,proto3" json:"deal,omitempty"`
}

func (x *DexPacket) Reset() {
	*x = DexPacket{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DexPacket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DexPacket) ProtoMessage() {}

func (x *DexPacket) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DexPacket.ProtoReflect.Descriptor instead.
func (*DexPacket) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{0}
}

func (x *DexPacket) GetDeal() *DKGDeal {
	if x != nil {
		return x.Deal
	}
	return nil
}

type DKGDeal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index      uint32      `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	IssuedDeal *IssuedDeal `protobuf:"bytes,2,opt,name=IssuedDeal,proto3" json:"IssuedDeal,omitempty"`
	Signature  []byte      `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *DKGDeal) Reset() {
	*x = DKGDeal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DKGDeal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DKGDeal) ProtoMessage() {}

func (x *DKGDeal) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DKGDeal.ProtoReflect.Descriptor instead.
func (*DKGDeal) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{1}
}

func (x *DKGDeal) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *DKGDeal) GetIssuedDeal() *IssuedDeal {
	if x != nil {
		return x.IssuedDeal
	}
	return nil
}

func (x *DKGDeal) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type IssuedDeal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DHKey     []byte `protobuf:"bytes,1,opt,name=DHKey,proto3" json:"DHKey,omitempty"`
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	Nonce     []byte `protobuf:"bytes,3,opt,name=nonce,proto3" json:"nonce,omitempty"`
	Cipher    []byte `protobuf:"bytes,4,opt,name=cipher,proto3" json:"cipher,omitempty"`
}

func (x *IssuedDeal) Reset() {
	*x = IssuedDeal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssuedDeal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssuedDeal) ProtoMessage() {}

func (x *IssuedDeal) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssuedDeal.ProtoReflect.Descriptor instead.
func (*IssuedDeal) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{2}
}

func (x *IssuedDeal) GetDHKey() []byte {
	if x != nil {
		return x.DHKey
	}
	return nil
}

func (x *IssuedDeal) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *IssuedDeal) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *IssuedDeal) GetCipher() []byte {
	if x != nil {
		return x.Cipher
	}
	return nil
}

type ResponsePacket struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Response *DKGResponse `protobuf:"bytes,1,opt,name=response,proto3" json:"response,omitempty"`
}

func (x *ResponsePacket) Reset() {
	*x = ResponsePacket{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResponsePacket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResponsePacket) ProtoMessage() {}

func (x *ResponsePacket) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResponsePacket.ProtoReflect.Descriptor instead.
func (*ResponsePacket) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{3}
}

func (x *ResponsePacket) GetResponse() *DKGResponse {
	if x != nil {
		return x.Response
	}
	return nil
}

type DKGResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index          uint32          `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	IssuedResponse *IssuedResponse `protobuf:"bytes,2,opt,name=IssuedResponse,proto3" json:"IssuedResponse,omitempty"`
}

func (x *DKGResponse) Reset() {
	*x = DKGResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DKGResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DKGResponse) ProtoMessage() {}

func (x *DKGResponse) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DKGResponse.ProtoReflect.Descriptor instead.
func (*DKGResponse) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{4}
}

func (x *DKGResponse) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *DKGResponse) GetIssuedResponse() *IssuedResponse {
	if x != nil {
		return x.IssuedResponse
	}
	return nil
}

type IssuedResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionID []byte `protobuf:"bytes,1,opt,name=sessionID,proto3" json:"sessionID,omitempty"`
	Index     uint32 `protobuf:"varint,2,opt,name=index,proto3" json:"index,omitempty"`
	Status    bool   `protobuf:"varint,3,opt,name=status,proto3" json:"status,omitempty"`
	Signature []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *IssuedResponse) Reset() {
	*x = IssuedResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssuedResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssuedResponse) ProtoMessage() {}

func (x *IssuedResponse) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssuedResponse.ProtoReflect.Descriptor instead.
func (*IssuedResponse) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{5}
}

func (x *IssuedResponse) GetSessionID() []byte {
	if x != nil {
		return x.SessionID
	}
	return nil
}

func (x *IssuedResponse) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *IssuedResponse) GetStatus() bool {
	if x != nil {
		return x.Status
	}
	return false
}

func (x *IssuedResponse) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_messages_proto protoreflect.FileDescriptor

var file_messages_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x02, 0x70, 0x62, 0x22, 0x2c, 0x0a, 0x09, 0x44, 0x65, 0x78, 0x50, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x12, 0x1f, 0x0a, 0x04, 0x64, 0x65, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0b, 0x2e, 0x70, 0x62, 0x2e, 0x44, 0x4b, 0x47, 0x44, 0x65, 0x61, 0x6c, 0x52, 0x04, 0x64, 0x65,
	0x61, 0x6c, 0x22, 0x6d, 0x0a, 0x07, 0x44, 0x4b, 0x47, 0x44, 0x65, 0x61, 0x6c, 0x12, 0x14, 0x0a,
	0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x12, 0x2e, 0x0a, 0x0a, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x44, 0x65, 0x61,
	0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x62, 0x2e, 0x49, 0x73, 0x73,
	0x75, 0x65, 0x64, 0x44, 0x65, 0x61, 0x6c, 0x52, 0x0a, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x44,
	0x65, 0x61, 0x6c, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x22, 0x6e, 0x0a, 0x0a, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x44, 0x65, 0x61, 0x6c, 0x12,
	0x14, 0x0a, 0x05, 0x44, 0x48, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05,
	0x44, 0x48, 0x4b, 0x65, 0x79, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x69, 0x70,
	0x68, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x63, 0x69, 0x70, 0x68, 0x65,
	0x72, 0x22, 0x3d, 0x0a, 0x0e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x50, 0x61, 0x63,
	0x6b, 0x65, 0x74, 0x12, 0x2b, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x62, 0x2e, 0x44, 0x4b, 0x47, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x5f, 0x0a, 0x0b, 0x44, 0x4b, 0x47, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x14, 0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x69, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x3a, 0x0a, 0x0e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x70, 0x62, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x52, 0x0e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x7a, 0x0a, 0x0e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x44,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49,
	0x44, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12,
	0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_messages_proto_rawDescOnce sync.Once
	file_messages_proto_rawDescData = file_messages_proto_rawDesc
)

func file_messages_proto_rawDescGZIP() []byte {
	file_messages_proto_rawDescOnce.Do(func() {
		file_messages_proto_rawDescData = protoimpl.X.CompressGZIP(file_messages_proto_rawDescData)
	})
	return file_messages_proto_rawDescData
}

var file_messages_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_messages_proto_goTypes = []interface{}{
	(*DexPacket)(nil),      // 0: pb.DexPacket
	(*DKGDeal)(nil),        // 1: pb.DKGDeal
	(*IssuedDeal)(nil),     // 2: pb.IssuedDeal
	(*ResponsePacket)(nil), // 3: pb.ResponsePacket
	(*DKGResponse)(nil),    // 4: pb.DKGResponse
	(*IssuedResponse)(nil), // 5: pb.IssuedResponse
}
var file_messages_proto_depIdxs = []int32{
	1, // 0: pb.DexPacket.deal:type_name -> pb.DKGDeal
	2, // 1: pb.DKGDeal.IssuedDeal:type_name -> pb.IssuedDeal
	4, // 2: pb.ResponsePacket.response:type_name -> pb.DKGResponse
	5, // 3: pb.DKGResponse.IssuedResponse:type_name -> pb.IssuedResponse
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_messages_proto_init() }
func file_messages_proto_init() {
	if File_messages_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_messages_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DexPacket); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_messages_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DKGDeal); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_messages_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IssuedDeal); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_messages_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResponsePacket); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_messages_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DKGResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_messages_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IssuedResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_messages_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_messages_proto_goTypes,
		DependencyIndexes: file_messages_proto_depIdxs,
		MessageInfos:      file_messages_proto_msgTypes,
	}.Build()
	File_messages_proto = out.File
	file_messages_proto_rawDesc = nil
	file_messages_proto_goTypes = nil
	file_messages_proto_depIdxs = nil
}
