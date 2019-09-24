// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api.proto

package api

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Error struct {
	Error                string   `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Error) Reset()         { *m = Error{} }
func (m *Error) String() string { return proto.CompactTextString(m) }
func (*Error) ProtoMessage()    {}
func (*Error) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{0}
}

func (m *Error) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Error.Unmarshal(m, b)
}
func (m *Error) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Error.Marshal(b, m, deterministic)
}
func (m *Error) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Error.Merge(m, src)
}
func (m *Error) XXX_Size() int {
	return xxx_messageInfo_Error.Size(m)
}
func (m *Error) XXX_DiscardUnknown() {
	xxx_messageInfo_Error.DiscardUnknown(m)
}

var xxx_messageInfo_Error proto.InternalMessageInfo

func (m *Error) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

type StartMeasurementResponse struct {
	MeasurementId        *MeasurementId `protobuf:"bytes,1,opt,name=MeasurementId,proto3" json:"MeasurementId,omitempty"`
	Error                *Error         `protobuf:"bytes,2,opt,name=Error,proto3" json:"Error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *StartMeasurementResponse) Reset()         { *m = StartMeasurementResponse{} }
func (m *StartMeasurementResponse) String() string { return proto.CompactTextString(m) }
func (*StartMeasurementResponse) ProtoMessage()    {}
func (*StartMeasurementResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{1}
}

func (m *StartMeasurementResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StartMeasurementResponse.Unmarshal(m, b)
}
func (m *StartMeasurementResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StartMeasurementResponse.Marshal(b, m, deterministic)
}
func (m *StartMeasurementResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StartMeasurementResponse.Merge(m, src)
}
func (m *StartMeasurementResponse) XXX_Size() int {
	return xxx_messageInfo_StartMeasurementResponse.Size(m)
}
func (m *StartMeasurementResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_StartMeasurementResponse.DiscardUnknown(m)
}

var xxx_messageInfo_StartMeasurementResponse proto.InternalMessageInfo

func (m *StartMeasurementResponse) GetMeasurementId() *MeasurementId {
	if m != nil {
		return m.MeasurementId
	}
	return nil
}

func (m *StartMeasurementResponse) GetError() *Error {
	if m != nil {
		return m.Error
	}
	return nil
}

type Meta struct {
	Description          string   `protobuf:"bytes,1,opt,name=Description,proto3" json:"Description,omitempty"`
	Host                 string   `protobuf:"bytes,2,opt,name=Host,proto3" json:"Host,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Meta) Reset()         { *m = Meta{} }
func (m *Meta) String() string { return proto.CompactTextString(m) }
func (*Meta) ProtoMessage()    {}
func (*Meta) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{2}
}

func (m *Meta) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Meta.Unmarshal(m, b)
}
func (m *Meta) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Meta.Marshal(b, m, deterministic)
}
func (m *Meta) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Meta.Merge(m, src)
}
func (m *Meta) XXX_Size() int {
	return xxx_messageInfo_Meta.Size(m)
}
func (m *Meta) XXX_DiscardUnknown() {
	xxx_messageInfo_Meta.DiscardUnknown(m)
}

var xxx_messageInfo_Meta proto.InternalMessageInfo

func (m *Meta) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *Meta) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

type MeasurementId struct {
	Id                   string   `protobuf:"bytes,1,opt,name=Id,proto3" json:"Id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MeasurementId) Reset()         { *m = MeasurementId{} }
func (m *MeasurementId) String() string { return proto.CompactTextString(m) }
func (*MeasurementId) ProtoMessage()    {}
func (*MeasurementId) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{3}
}

func (m *MeasurementId) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MeasurementId.Unmarshal(m, b)
}
func (m *MeasurementId) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MeasurementId.Marshal(b, m, deterministic)
}
func (m *MeasurementId) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MeasurementId.Merge(m, src)
}
func (m *MeasurementId) XXX_Size() int {
	return xxx_messageInfo_MeasurementId.Size(m)
}
func (m *MeasurementId) XXX_DiscardUnknown() {
	xxx_messageInfo_MeasurementId.DiscardUnknown(m)
}

var xxx_messageInfo_MeasurementId proto.InternalMessageInfo

func (m *MeasurementId) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type LogEntry struct {
	Certificate          []byte   `protobuf:"bytes,1,opt,name=Certificate,proto3" json:"Certificate,omitempty"`
	Index                int64    `protobuf:"varint,2,opt,name=Index,proto3" json:"Index,omitempty"`
	Timestamp            int64    `protobuf:"varint,3,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
	Log                  *Log     `protobuf:"bytes,4,opt,name=Log,proto3" json:"Log,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LogEntry) Reset()         { *m = LogEntry{} }
func (m *LogEntry) String() string { return proto.CompactTextString(m) }
func (*LogEntry) ProtoMessage()    {}
func (*LogEntry) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{4}
}

func (m *LogEntry) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LogEntry.Unmarshal(m, b)
}
func (m *LogEntry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LogEntry.Marshal(b, m, deterministic)
}
func (m *LogEntry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LogEntry.Merge(m, src)
}
func (m *LogEntry) XXX_Size() int {
	return xxx_messageInfo_LogEntry.Size(m)
}
func (m *LogEntry) XXX_DiscardUnknown() {
	xxx_messageInfo_LogEntry.DiscardUnknown(m)
}

var xxx_messageInfo_LogEntry proto.InternalMessageInfo

func (m *LogEntry) GetCertificate() []byte {
	if m != nil {
		return m.Certificate
	}
	return nil
}

func (m *LogEntry) GetIndex() int64 {
	if m != nil {
		return m.Index
	}
	return 0
}

func (m *LogEntry) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *LogEntry) GetLog() *Log {
	if m != nil {
		return m.Log
	}
	return nil
}

type Log struct {
	Description          string   `protobuf:"bytes,1,opt,name=Description,proto3" json:"Description,omitempty"`
	Key                  string   `protobuf:"bytes,2,opt,name=Key,proto3" json:"Key,omitempty"`
	Url                  string   `protobuf:"bytes,3,opt,name=Url,proto3" json:"Url,omitempty"`
	MaximumMergeDelay    int64    `protobuf:"varint,4,opt,name=MaximumMergeDelay,proto3" json:"MaximumMergeDelay,omitempty"`
	OperatedBy           []int64  `protobuf:"varint,5,rep,packed,name=OperatedBy,proto3" json:"OperatedBy,omitempty"`
	DnsApiEndpoint       string   `protobuf:"bytes,6,opt,name=DnsApiEndpoint,proto3" json:"DnsApiEndpoint,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Log) Reset()         { *m = Log{} }
func (m *Log) String() string { return proto.CompactTextString(m) }
func (*Log) ProtoMessage()    {}
func (*Log) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{5}
}

func (m *Log) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Log.Unmarshal(m, b)
}
func (m *Log) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Log.Marshal(b, m, deterministic)
}
func (m *Log) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Log.Merge(m, src)
}
func (m *Log) XXX_Size() int {
	return xxx_messageInfo_Log.Size(m)
}
func (m *Log) XXX_DiscardUnknown() {
	xxx_messageInfo_Log.DiscardUnknown(m)
}

var xxx_messageInfo_Log proto.InternalMessageInfo

func (m *Log) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *Log) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *Log) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *Log) GetMaximumMergeDelay() int64 {
	if m != nil {
		return m.MaximumMergeDelay
	}
	return 0
}

func (m *Log) GetOperatedBy() []int64 {
	if m != nil {
		return m.OperatedBy
	}
	return nil
}

func (m *Log) GetDnsApiEndpoint() string {
	if m != nil {
		return m.DnsApiEndpoint
	}
	return ""
}

type ZoneEntry struct {
	Fqdn                 string   `protobuf:"bytes,1,opt,name=Fqdn,proto3" json:"Fqdn,omitempty"`
	Timestamp            int64    `protobuf:"varint,2,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ZoneEntry) Reset()         { *m = ZoneEntry{} }
func (m *ZoneEntry) String() string { return proto.CompactTextString(m) }
func (*ZoneEntry) ProtoMessage()    {}
func (*ZoneEntry) Descriptor() ([]byte, []int) {
	return fileDescriptor_00212fb1f9d3bf1c, []int{6}
}

func (m *ZoneEntry) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ZoneEntry.Unmarshal(m, b)
}
func (m *ZoneEntry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ZoneEntry.Marshal(b, m, deterministic)
}
func (m *ZoneEntry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ZoneEntry.Merge(m, src)
}
func (m *ZoneEntry) XXX_Size() int {
	return xxx_messageInfo_ZoneEntry.Size(m)
}
func (m *ZoneEntry) XXX_DiscardUnknown() {
	xxx_messageInfo_ZoneEntry.DiscardUnknown(m)
}

var xxx_messageInfo_ZoneEntry proto.InternalMessageInfo

func (m *ZoneEntry) GetFqdn() string {
	if m != nil {
		return m.Fqdn
	}
	return ""
}

func (m *ZoneEntry) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func init() {
	proto.RegisterType((*Error)(nil), "Error")
	proto.RegisterType((*StartMeasurementResponse)(nil), "StartMeasurementResponse")
	proto.RegisterType((*Meta)(nil), "Meta")
	proto.RegisterType((*MeasurementId)(nil), "MeasurementId")
	proto.RegisterType((*LogEntry)(nil), "LogEntry")
	proto.RegisterType((*Log)(nil), "Log")
	proto.RegisterType((*ZoneEntry)(nil), "ZoneEntry")
}

func init() { proto.RegisterFile("api.proto", fileDescriptor_00212fb1f9d3bf1c) }

var fileDescriptor_00212fb1f9d3bf1c = []byte{
	// 464 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x53, 0x5d, 0x8b, 0xd3, 0x40,
	0x14, 0xdd, 0x36, 0x4d, 0x31, 0xb7, 0x1a, 0xd7, 0x41, 0x24, 0x2e, 0xab, 0x96, 0x80, 0xcb, 0x82,
	0x12, 0xa1, 0x7e, 0x3c, 0xe9, 0xc3, 0xba, 0xed, 0x62, 0xb1, 0x55, 0x98, 0xea, 0x8b, 0x6f, 0xe3,
	0xe6, 0x1a, 0x06, 0x9a, 0x99, 0x71, 0x32, 0x0b, 0xed, 0x7f, 0xf1, 0xcf, 0xf8, 0xcf, 0x64, 0x6e,
	0xb2, 0x36, 0x8d, 0x2c, 0xf8, 0x76, 0xe7, 0xcc, 0x3d, 0x73, 0xee, 0x3d, 0x39, 0x81, 0x48, 0x18,
	0x99, 0x19, 0xab, 0x9d, 0x4e, 0x1f, 0x41, 0x38, 0xb3, 0x56, 0x5b, 0x76, 0x1f, 0x42, 0xf4, 0x45,
	0xd2, 0x1b, 0xf7, 0x4e, 0x23, 0x5e, 0x1f, 0x52, 0x05, 0xc9, 0xca, 0x09, 0xeb, 0x96, 0x28, 0xaa,
	0x2b, 0x8b, 0x25, 0x2a, 0xc7, 0xb1, 0x32, 0x5a, 0x55, 0xc8, 0x5e, 0xc1, 0x9d, 0x16, 0x3c, 0xcf,
	0x89, 0x39, 0x9a, 0xc4, 0xd9, 0x1e, 0xca, 0xf7, 0x9b, 0xd8, 0x71, 0x23, 0x98, 0xf4, 0xa9, 0x7b,
	0x98, 0xd1, 0x89, 0xd7, 0x60, 0xfa, 0x16, 0x06, 0x4b, 0x74, 0x82, 0x8d, 0x61, 0x34, 0xc5, 0xea,
	0xd2, 0x4a, 0xe3, 0xa4, 0x56, 0xcd, 0x4c, 0x6d, 0x88, 0x31, 0x18, 0x7c, 0xd0, 0x95, 0xa3, 0x67,
	0x22, 0x4e, 0x75, 0xfa, 0xa4, 0x33, 0x11, 0x8b, 0xa1, 0xdf, 0xcc, 0x15, 0xf1, 0xfe, 0x3c, 0x4f,
	0x37, 0x70, 0x6b, 0xa1, 0x8b, 0x99, 0x72, 0x76, 0xeb, 0x25, 0xce, 0xd1, 0x3a, 0xf9, 0x43, 0x5e,
	0x0a, 0x87, 0xd4, 0x74, 0x9b, 0xb7, 0x21, 0x6f, 0xc9, 0x5c, 0xe5, 0xb8, 0x21, 0x8d, 0x80, 0xd7,
	0x07, 0x76, 0x0c, 0xd1, 0x17, 0x59, 0x62, 0xe5, 0x44, 0x69, 0x92, 0x80, 0x6e, 0x76, 0x00, 0x7b,
	0x00, 0xc1, 0x42, 0x17, 0xc9, 0x80, 0x96, 0x1b, 0x64, 0x0b, 0x5d, 0x70, 0x0f, 0xa4, 0xbf, 0x7b,
	0x74, 0xf1, 0x1f, 0x8b, 0x1d, 0x42, 0xf0, 0x11, 0xb7, 0xcd, 0x5e, 0xbe, 0xf4, 0xc8, 0x57, 0xbb,
	0x26, 0xad, 0x88, 0xfb, 0x92, 0x3d, 0x87, 0x7b, 0x4b, 0xb1, 0x91, 0xe5, 0x55, 0xb9, 0x44, 0x5b,
	0xe0, 0x14, 0xd7, 0x62, 0x4b, 0x9a, 0x01, 0xff, 0xf7, 0x82, 0x3d, 0x06, 0xf8, 0x6c, 0xd0, 0x0a,
	0x87, 0xf9, 0xfb, 0x6d, 0x12, 0x8e, 0x83, 0xd3, 0x80, 0xb7, 0x10, 0x76, 0x02, 0xf1, 0x54, 0x55,
	0x67, 0x46, 0xce, 0x54, 0x6e, 0xb4, 0x54, 0x2e, 0x19, 0x92, 0x54, 0x07, 0x4d, 0xdf, 0x41, 0xf4,
	0x4d, 0x2b, 0xac, 0xed, 0x63, 0x30, 0xb8, 0xf8, 0x99, 0x5f, 0x6f, 0x40, 0xf5, 0xbe, 0x35, 0xfd,
	0x8e, 0x35, 0x93, 0x5f, 0x3d, 0x88, 0x5b, 0x9f, 0xe7, 0xcc, 0x48, 0xf6, 0x06, 0x0e, 0xbb, 0xf1,
	0x62, 0x61, 0xe6, 0x13, 0x70, 0xf4, 0x30, 0xbb, 0x29, 0x78, 0xe9, 0x01, 0x7b, 0x06, 0x77, 0x57,
	0x4e, 0x9b, 0x36, 0xad, 0x13, 0xbb, 0xa3, 0x26, 0x58, 0xe9, 0x01, 0x7b, 0x0a, 0xd1, 0x27, 0xdc,
	0xb8, 0x95, 0x13, 0x05, 0xde, 0xdc, 0x36, 0x79, 0x01, 0xe1, 0x39, 0x0d, 0x75, 0x42, 0x8f, 0x5b,
	0x6c, 0x92, 0x22, 0xb1, 0x62, 0x51, 0x76, 0x1d, 0x9b, 0x16, 0xe1, 0x35, 0x8c, 0xbc, 0x1d, 0x17,
	0x72, 0x8d, 0x35, 0x2d, 0x26, 0xda, 0xce, 0x22, 0xc8, 0xfe, 0xd6, 0x3b, 0xda, 0xf7, 0x21, 0xfd,
	0x78, 0x2f, 0xff, 0x04, 0x00, 0x00, 0xff, 0xff, 0xaa, 0x68, 0x9f, 0x68, 0x85, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MeasurementApiClient is the client API for MeasurementApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MeasurementApiClient interface {
	StartMeasurement(ctx context.Context, in *Meta, opts ...grpc.CallOption) (*StartMeasurementResponse, error)
	StopMeasurement(ctx context.Context, in *MeasurementId, opts ...grpc.CallOption) (*Error, error)
	NextStage(ctx context.Context, in *MeasurementId, opts ...grpc.CallOption) (*Error, error)
}

type measurementApiClient struct {
	cc *grpc.ClientConn
}

func NewMeasurementApiClient(cc *grpc.ClientConn) MeasurementApiClient {
	return &measurementApiClient{cc}
}

func (c *measurementApiClient) StartMeasurement(ctx context.Context, in *Meta, opts ...grpc.CallOption) (*StartMeasurementResponse, error) {
	out := new(StartMeasurementResponse)
	err := c.cc.Invoke(ctx, "/MeasurementApi/StartMeasurement", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *measurementApiClient) StopMeasurement(ctx context.Context, in *MeasurementId, opts ...grpc.CallOption) (*Error, error) {
	out := new(Error)
	err := c.cc.Invoke(ctx, "/MeasurementApi/StopMeasurement", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *measurementApiClient) NextStage(ctx context.Context, in *MeasurementId, opts ...grpc.CallOption) (*Error, error) {
	out := new(Error)
	err := c.cc.Invoke(ctx, "/MeasurementApi/NextStage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MeasurementApiServer is the server API for MeasurementApi service.
type MeasurementApiServer interface {
	StartMeasurement(context.Context, *Meta) (*StartMeasurementResponse, error)
	StopMeasurement(context.Context, *MeasurementId) (*Error, error)
	NextStage(context.Context, *MeasurementId) (*Error, error)
}

func RegisterMeasurementApiServer(s *grpc.Server, srv MeasurementApiServer) {
	s.RegisterService(&_MeasurementApi_serviceDesc, srv)
}

func _MeasurementApi_StartMeasurement_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Meta)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MeasurementApiServer).StartMeasurement(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/MeasurementApi/StartMeasurement",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MeasurementApiServer).StartMeasurement(ctx, req.(*Meta))
	}
	return interceptor(ctx, in, info, handler)
}

func _MeasurementApi_StopMeasurement_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MeasurementId)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MeasurementApiServer).StopMeasurement(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/MeasurementApi/StopMeasurement",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MeasurementApiServer).StopMeasurement(ctx, req.(*MeasurementId))
	}
	return interceptor(ctx, in, info, handler)
}

func _MeasurementApi_NextStage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MeasurementId)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MeasurementApiServer).NextStage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/MeasurementApi/NextStage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MeasurementApiServer).NextStage(ctx, req.(*MeasurementId))
	}
	return interceptor(ctx, in, info, handler)
}

var _MeasurementApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "MeasurementApi",
	HandlerType: (*MeasurementApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StartMeasurement",
			Handler:    _MeasurementApi_StartMeasurement_Handler,
		},
		{
			MethodName: "StopMeasurement",
			Handler:    _MeasurementApi_StopMeasurement_Handler,
		},
		{
			MethodName: "NextStage",
			Handler:    _MeasurementApi_NextStage_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}

// CtApiClient is the client API for CtApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CtApiClient interface {
	StoreLogEntries(ctx context.Context, in *LogEntry, opts ...grpc.CallOption) (*Error, error)
}

type ctApiClient struct {
	cc *grpc.ClientConn
}

func NewCtApiClient(cc *grpc.ClientConn) CtApiClient {
	return &ctApiClient{cc}
}

func (c *ctApiClient) StoreLogEntries(ctx context.Context, in *LogEntry, opts ...grpc.CallOption) (*Error, error) {
	out := new(Error)
	err := c.cc.Invoke(ctx, "/CtApi/StoreLogEntries", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CtApiServer is the server API for CtApi service.
type CtApiServer interface {
	StoreLogEntries(context.Context, *LogEntry) (*Error, error)
}

func RegisterCtApiServer(s *grpc.Server, srv CtApiServer) {
	s.RegisterService(&_CtApi_serviceDesc, srv)
}

func _CtApi_StoreLogEntries_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogEntry)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CtApiServer).StoreLogEntries(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/CtApi/StoreLogEntries",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CtApiServer).StoreLogEntries(ctx, req.(*LogEntry))
	}
	return interceptor(ctx, in, info, handler)
}

var _CtApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "CtApi",
	HandlerType: (*CtApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StoreLogEntries",
			Handler:    _CtApi_StoreLogEntries_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}

// ZoneFileApiClient is the client API for ZoneFileApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ZoneFileApiClient interface {
	StoreZoneEntry(ctx context.Context, in *ZoneEntry, opts ...grpc.CallOption) (*Error, error)
}

type zoneFileApiClient struct {
	cc *grpc.ClientConn
}

func NewZoneFileApiClient(cc *grpc.ClientConn) ZoneFileApiClient {
	return &zoneFileApiClient{cc}
}

func (c *zoneFileApiClient) StoreZoneEntry(ctx context.Context, in *ZoneEntry, opts ...grpc.CallOption) (*Error, error) {
	out := new(Error)
	err := c.cc.Invoke(ctx, "/ZoneFileApi/StoreZoneEntry", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ZoneFileApiServer is the server API for ZoneFileApi service.
type ZoneFileApiServer interface {
	StoreZoneEntry(context.Context, *ZoneEntry) (*Error, error)
}

func RegisterZoneFileApiServer(s *grpc.Server, srv ZoneFileApiServer) {
	s.RegisterService(&_ZoneFileApi_serviceDesc, srv)
}

func _ZoneFileApi_StoreZoneEntry_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ZoneEntry)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ZoneFileApiServer).StoreZoneEntry(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ZoneFileApi/StoreZoneEntry",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ZoneFileApiServer).StoreZoneEntry(ctx, req.(*ZoneEntry))
	}
	return interceptor(ctx, in, info, handler)
}

var _ZoneFileApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "ZoneFileApi",
	HandlerType: (*ZoneFileApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StoreZoneEntry",
			Handler:    _ZoneFileApi_StoreZoneEntry_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}
