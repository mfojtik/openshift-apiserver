// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/api/endpoint.proto

package serviceconfig // import "google.golang.org/genproto/googleapis/api/serviceconfig"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// `Endpoint` describes a network endpoint that serves a set of APIs.
// A service may expose any number of endpoints, and all endpoints share the
// same service configuration, such as quota configuration and monitoring
// configuration.
//
// Example service configuration:
//
//     name: library-example.googleapis.com
//     endpoints:
//       # Below entry makes 'google.example.library.v1.Library'
//       # API be served from endpoint address library-example.googleapis.com.
//       # It also allows HTTP OPTIONS calls to be passed to the backend, for
//       # it to decide whether the subsequent cross-origin request is
//       # allowed to proceed.
//     - name: library-example.googleapis.com
//       allow_cors: true
type Endpoint struct {
	// The canonical name of this endpoint.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// DEPRECATED: This field is no longer supported. Instead of using aliases,
	// please specify multiple [google.api.Endpoint][google.api.Endpoint] for each of the intended
	// aliases.
	//
	// Additional names that this endpoint will be hosted on.
	Aliases []string `protobuf:"bytes,2,rep,name=aliases,proto3" json:"aliases,omitempty"` // Deprecated: Do not use.
	// The list of features enabled on this endpoint.
	Features []string `protobuf:"bytes,4,rep,name=features,proto3" json:"features,omitempty"`
	// The specification of an Internet routable address of API frontend that will
	// handle requests to this [API
	// Endpoint](https://cloud.google.com/apis/design/glossary). It should be
	// either a valid IPv4 address or a fully-qualified domain name. For example,
	// "8.8.8.8" or "myservice.appspot.com".
	Target string `protobuf:"bytes,101,opt,name=target,proto3" json:"target,omitempty"`
	// Allowing
	// [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing), aka
	// cross-domain traffic, would allow the backends served from this endpoint to
	// receive and respond to HTTP OPTIONS requests. The response will be used by
	// the browser to determine whether the subsequent cross-origin request is
	// allowed to proceed.
	AllowCors            bool     `protobuf:"varint,5,opt,name=allow_cors,json=allowCors,proto3" json:"allow_cors,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Endpoint) Reset()         { *m = Endpoint{} }
func (m *Endpoint) String() string { return proto.CompactTextString(m) }
func (*Endpoint) ProtoMessage()    {}
func (*Endpoint) Descriptor() ([]byte, []int) {
	return fileDescriptor_endpoint_c5a971e7963d7d02, []int{0}
}
func (m *Endpoint) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Endpoint.Unmarshal(m, b)
}
func (m *Endpoint) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Endpoint.Marshal(b, m, deterministic)
}
func (dst *Endpoint) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Endpoint.Merge(dst, src)
}
func (m *Endpoint) XXX_Size() int {
	return xxx_messageInfo_Endpoint.Size(m)
}
func (m *Endpoint) XXX_DiscardUnknown() {
	xxx_messageInfo_Endpoint.DiscardUnknown(m)
}

var xxx_messageInfo_Endpoint proto.InternalMessageInfo

func (m *Endpoint) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Deprecated: Do not use.
func (m *Endpoint) GetAliases() []string {
	if m != nil {
		return m.Aliases
	}
	return nil
}

func (m *Endpoint) GetFeatures() []string {
	if m != nil {
		return m.Features
	}
	return nil
}

func (m *Endpoint) GetTarget() string {
	if m != nil {
		return m.Target
	}
	return ""
}

func (m *Endpoint) GetAllowCors() bool {
	if m != nil {
		return m.AllowCors
	}
	return false
}

func init() {
	proto.RegisterType((*Endpoint)(nil), "google.api.Endpoint")
}

func init() { proto.RegisterFile("google/api/endpoint.proto", fileDescriptor_endpoint_c5a971e7963d7d02) }

var fileDescriptor_endpoint_c5a971e7963d7d02 = []byte{
	// 236 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x8f, 0xc1, 0x4a, 0xc4, 0x30,
	0x10, 0x86, 0x49, 0xad, 0x6b, 0x3b, 0xa0, 0x87, 0x1c, 0x24, 0x8a, 0x42, 0xf1, 0xd4, 0x53, 0x7b,
	0xf0, 0xe8, 0xc9, 0xca, 0x22, 0xde, 0x4a, 0x8f, 0x5e, 0x64, 0xac, 0xb3, 0x21, 0x90, 0xcd, 0x84,
	0x24, 0xea, 0x63, 0xf8, 0x0e, 0x3e, 0xa9, 0x6c, 0xb6, 0xab, 0x78, 0xcb, 0xff, 0x7f, 0x64, 0xf8,
	0x7e, 0xb8, 0xd0, 0xcc, 0xda, 0x52, 0x8f, 0xde, 0xf4, 0xe4, 0xde, 0x3c, 0x1b, 0x97, 0x3a, 0x1f,
	0x38, 0xb1, 0x84, 0x3d, 0xea, 0xd0, 0x9b, 0x9b, 0x2f, 0x01, 0xd5, 0x7a, 0xc1, 0x52, 0x42, 0xe9,
	0x70, 0x4b, 0x4a, 0x34, 0xa2, 0xad, 0xa7, 0xfc, 0x96, 0x57, 0x70, 0x82, 0xd6, 0x60, 0xa4, 0xa8,
	0x8a, 0xe6, 0xa8, 0xad, 0x87, 0x42, 0x89, 0xe9, 0x50, 0xc9, 0x4b, 0xa8, 0x36, 0x84, 0xe9, 0x3d,
	0x50, 0x54, 0xe5, 0x0e, 0x4f, 0xbf, 0x59, 0x9e, 0xc3, 0x2a, 0x61, 0xd0, 0x94, 0x14, 0xe5, 0x7b,
	0x4b, 0x92, 0xd7, 0x00, 0x68, 0x2d, 0x7f, 0xbe, 0xcc, 0x1c, 0xa2, 0x3a, 0x6e, 0x44, 0x5b, 0x4d,
	0x75, 0x6e, 0x1e, 0x38, 0xc4, 0x81, 0xe1, 0x6c, 0xe6, 0x6d, 0xf7, 0xe7, 0x38, 0x9c, 0x1e, 0x04,
	0xc7, 0x9d, 0xfe, 0x28, 0x9e, 0xd7, 0x0b, 0xd4, 0x6c, 0xd1, 0xe9, 0x8e, 0x83, 0xee, 0x35, 0xb9,
	0x3c, 0xae, 0xdf, 0x23, 0xf4, 0x26, 0xe6, 0xe9, 0x91, 0xc2, 0x87, 0x99, 0x69, 0x66, 0xb7, 0x31,
	0xfa, 0xee, 0x5f, 0xfa, 0x2e, 0xca, 0xc7, 0xfb, 0xf1, 0xe9, 0x75, 0x95, 0x3f, 0xde, 0xfe, 0x04,
	0x00, 0x00, 0xff, 0xff, 0xa5, 0x38, 0x4b, 0xb3, 0x32, 0x01, 0x00, 0x00,
}
