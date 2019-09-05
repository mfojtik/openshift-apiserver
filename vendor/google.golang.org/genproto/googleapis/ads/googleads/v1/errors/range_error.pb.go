// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/errors/range_error.proto

package errors // import "google.golang.org/genproto/googleapis/ads/googleads/v1/errors"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Enum describing possible range errors.
type RangeErrorEnum_RangeError int32

const (
	// Enum unspecified.
	RangeErrorEnum_UNSPECIFIED RangeErrorEnum_RangeError = 0
	// The received error code is not known in this version.
	RangeErrorEnum_UNKNOWN RangeErrorEnum_RangeError = 1
	// Too low.
	RangeErrorEnum_TOO_LOW RangeErrorEnum_RangeError = 2
	// Too high.
	RangeErrorEnum_TOO_HIGH RangeErrorEnum_RangeError = 3
)

var RangeErrorEnum_RangeError_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "TOO_LOW",
	3: "TOO_HIGH",
}
var RangeErrorEnum_RangeError_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"TOO_LOW":     2,
	"TOO_HIGH":    3,
}

func (x RangeErrorEnum_RangeError) String() string {
	return proto.EnumName(RangeErrorEnum_RangeError_name, int32(x))
}
func (RangeErrorEnum_RangeError) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_range_error_922145fa23db5891, []int{0, 0}
}

// Container for enum describing possible range errors.
type RangeErrorEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RangeErrorEnum) Reset()         { *m = RangeErrorEnum{} }
func (m *RangeErrorEnum) String() string { return proto.CompactTextString(m) }
func (*RangeErrorEnum) ProtoMessage()    {}
func (*RangeErrorEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_range_error_922145fa23db5891, []int{0}
}
func (m *RangeErrorEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RangeErrorEnum.Unmarshal(m, b)
}
func (m *RangeErrorEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RangeErrorEnum.Marshal(b, m, deterministic)
}
func (dst *RangeErrorEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RangeErrorEnum.Merge(dst, src)
}
func (m *RangeErrorEnum) XXX_Size() int {
	return xxx_messageInfo_RangeErrorEnum.Size(m)
}
func (m *RangeErrorEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_RangeErrorEnum.DiscardUnknown(m)
}

var xxx_messageInfo_RangeErrorEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*RangeErrorEnum)(nil), "google.ads.googleads.v1.errors.RangeErrorEnum")
	proto.RegisterEnum("google.ads.googleads.v1.errors.RangeErrorEnum_RangeError", RangeErrorEnum_RangeError_name, RangeErrorEnum_RangeError_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/errors/range_error.proto", fileDescriptor_range_error_922145fa23db5891)
}

var fileDescriptor_range_error_922145fa23db5891 = []byte{
	// 292 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x90, 0xc1, 0x4a, 0xf3, 0x40,
	0x14, 0x85, 0xff, 0xa4, 0xf0, 0x2b, 0x53, 0xb1, 0x21, 0x4b, 0x91, 0x2e, 0xf2, 0x00, 0x33, 0x06,
	0x77, 0xe3, 0x2a, 0xb5, 0x31, 0x0d, 0x4a, 0x12, 0xd4, 0x26, 0x20, 0x81, 0x32, 0x9a, 0x30, 0x04,
	0xda, 0x99, 0x30, 0x13, 0xfb, 0x40, 0x2e, 0x7d, 0x14, 0x1f, 0xa5, 0x4f, 0x21, 0x93, 0x6b, 0xd2,
	0x95, 0xae, 0xe6, 0xdc, 0xe1, 0x3b, 0xe7, 0x1e, 0x2e, 0xba, 0xe2, 0x52, 0xf2, 0x6d, 0x4d, 0x58,
	0xa5, 0x09, 0x48, 0xa3, 0xf6, 0x3e, 0xa9, 0x95, 0x92, 0x4a, 0x13, 0xc5, 0x04, 0xaf, 0x37, 0xfd,
	0x80, 0x5b, 0x25, 0x3b, 0xe9, 0xce, 0x01, 0xc3, 0xac, 0xd2, 0x78, 0x74, 0xe0, 0xbd, 0x8f, 0xc1,
	0x71, 0x71, 0x39, 0x24, 0xb6, 0x0d, 0x61, 0x42, 0xc8, 0x8e, 0x75, 0x8d, 0x14, 0x1a, 0xdc, 0x5e,
	0x81, 0xce, 0x1f, 0x4d, 0x64, 0x68, 0xe0, 0x50, 0xbc, 0xef, 0xbc, 0x10, 0xa1, 0xe3, 0x8f, 0x3b,
	0x43, 0xd3, 0x75, 0xf2, 0x94, 0x85, 0xb7, 0xf1, 0x5d, 0x1c, 0x2e, 0x9d, 0x7f, 0xee, 0x14, 0x9d,
	0xac, 0x93, 0xfb, 0x24, 0x2d, 0x12, 0xc7, 0x32, 0xc3, 0x73, 0x9a, 0x6e, 0x1e, 0xd2, 0xc2, 0xb1,
	0xdd, 0x33, 0x74, 0x6a, 0x86, 0x55, 0x1c, 0xad, 0x9c, 0xc9, 0xe2, 0x60, 0x21, 0xef, 0x4d, 0xee,
	0xf0, 0xdf, 0xed, 0x16, 0xb3, 0xe3, 0xae, 0xcc, 0x14, 0xca, 0xac, 0x97, 0xe5, 0x8f, 0x85, 0xcb,
	0x2d, 0x13, 0x1c, 0x4b, 0xc5, 0x09, 0xaf, 0x45, 0x5f, 0x77, 0x38, 0x49, 0xdb, 0xe8, 0xdf, 0x2e,
	0x74, 0x03, 0xcf, 0x87, 0x3d, 0x89, 0x82, 0xe0, 0xd3, 0x9e, 0x47, 0x10, 0x16, 0x54, 0x1a, 0x83,
	0x34, 0x2a, 0xf7, 0x71, 0xbf, 0x52, 0x7f, 0x0d, 0x40, 0x19, 0x54, 0xba, 0x1c, 0x81, 0x32, 0xf7,
	0x4b, 0x00, 0x0e, 0xb6, 0x07, 0xbf, 0x94, 0x06, 0x95, 0xa6, 0x74, 0x44, 0x28, 0xcd, 0x7d, 0x4a,
	0x01, 0x7a, 0xfd, 0xdf, 0xb7, 0xbb, 0xfe, 0x0e, 0x00, 0x00, 0xff, 0xff, 0x05, 0xb6, 0x0f, 0x2d,
	0xbe, 0x01, 0x00, 0x00,
}
