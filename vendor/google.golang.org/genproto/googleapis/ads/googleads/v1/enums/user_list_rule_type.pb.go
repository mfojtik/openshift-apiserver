// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/ads/googleads/v1/enums/user_list_rule_type.proto

package enums // import "google.golang.org/genproto/googleapis/ads/googleads/v1/enums"

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

// Enum describing possible user list rule types.
type UserListRuleTypeEnum_UserListRuleType int32

const (
	// Not specified.
	UserListRuleTypeEnum_UNSPECIFIED UserListRuleTypeEnum_UserListRuleType = 0
	// Used for return value only. Represents value unknown in this version.
	UserListRuleTypeEnum_UNKNOWN UserListRuleTypeEnum_UserListRuleType = 1
	// Conjunctive normal form.
	UserListRuleTypeEnum_AND_OF_ORS UserListRuleTypeEnum_UserListRuleType = 2
	// Disjunctive normal form.
	UserListRuleTypeEnum_OR_OF_ANDS UserListRuleTypeEnum_UserListRuleType = 3
)

var UserListRuleTypeEnum_UserListRuleType_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "UNKNOWN",
	2: "AND_OF_ORS",
	3: "OR_OF_ANDS",
}
var UserListRuleTypeEnum_UserListRuleType_value = map[string]int32{
	"UNSPECIFIED": 0,
	"UNKNOWN":     1,
	"AND_OF_ORS":  2,
	"OR_OF_ANDS":  3,
}

func (x UserListRuleTypeEnum_UserListRuleType) String() string {
	return proto.EnumName(UserListRuleTypeEnum_UserListRuleType_name, int32(x))
}
func (UserListRuleTypeEnum_UserListRuleType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_user_list_rule_type_835c5d2bbaa50c25, []int{0, 0}
}

// Rule based user list rule type.
type UserListRuleTypeEnum struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UserListRuleTypeEnum) Reset()         { *m = UserListRuleTypeEnum{} }
func (m *UserListRuleTypeEnum) String() string { return proto.CompactTextString(m) }
func (*UserListRuleTypeEnum) ProtoMessage()    {}
func (*UserListRuleTypeEnum) Descriptor() ([]byte, []int) {
	return fileDescriptor_user_list_rule_type_835c5d2bbaa50c25, []int{0}
}
func (m *UserListRuleTypeEnum) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UserListRuleTypeEnum.Unmarshal(m, b)
}
func (m *UserListRuleTypeEnum) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UserListRuleTypeEnum.Marshal(b, m, deterministic)
}
func (dst *UserListRuleTypeEnum) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UserListRuleTypeEnum.Merge(dst, src)
}
func (m *UserListRuleTypeEnum) XXX_Size() int {
	return xxx_messageInfo_UserListRuleTypeEnum.Size(m)
}
func (m *UserListRuleTypeEnum) XXX_DiscardUnknown() {
	xxx_messageInfo_UserListRuleTypeEnum.DiscardUnknown(m)
}

var xxx_messageInfo_UserListRuleTypeEnum proto.InternalMessageInfo

func init() {
	proto.RegisterType((*UserListRuleTypeEnum)(nil), "google.ads.googleads.v1.enums.UserListRuleTypeEnum")
	proto.RegisterEnum("google.ads.googleads.v1.enums.UserListRuleTypeEnum_UserListRuleType", UserListRuleTypeEnum_UserListRuleType_name, UserListRuleTypeEnum_UserListRuleType_value)
}

func init() {
	proto.RegisterFile("google/ads/googleads/v1/enums/user_list_rule_type.proto", fileDescriptor_user_list_rule_type_835c5d2bbaa50c25)
}

var fileDescriptor_user_list_rule_type_835c5d2bbaa50c25 = []byte{
	// 315 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x50, 0xdd, 0x4a, 0xc3, 0x30,
	0x14, 0x76, 0x1d, 0x28, 0x64, 0xa0, 0xa5, 0xe8, 0x8d, 0xb8, 0x8b, 0xed, 0x01, 0x52, 0x8a, 0x17,
	0x42, 0xbc, 0xca, 0xdc, 0x0f, 0x43, 0x69, 0xcb, 0xe6, 0x26, 0x48, 0xa1, 0x54, 0x1b, 0x62, 0xa1,
	0x4b, 0x4a, 0x4f, 0x3a, 0xd8, 0xeb, 0x78, 0xe9, 0xa3, 0xf8, 0x28, 0x7b, 0x0a, 0x49, 0xe2, 0x7a,
	0x31, 0xd0, 0x9b, 0xf0, 0x9d, 0xf3, 0x7d, 0xdf, 0xc9, 0x77, 0x0e, 0xba, 0xe3, 0x52, 0xf2, 0x92,
	0xf9, 0x59, 0x0e, 0xbe, 0x85, 0x1a, 0x6d, 0x03, 0x9f, 0x89, 0x66, 0x03, 0x7e, 0x03, 0xac, 0x4e,
	0xcb, 0x02, 0x54, 0x5a, 0x37, 0x25, 0x4b, 0xd5, 0xae, 0x62, 0xb8, 0xaa, 0xa5, 0x92, 0x5e, 0xdf,
	0xaa, 0x71, 0x96, 0x03, 0x6e, 0x8d, 0x78, 0x1b, 0x60, 0x63, 0xbc, 0xbe, 0x39, 0xcc, 0xad, 0x0a,
	0x3f, 0x13, 0x42, 0xaa, 0x4c, 0x15, 0x52, 0x80, 0x35, 0x0f, 0x3f, 0xd0, 0xe5, 0x0a, 0x58, 0xfd,
	0x54, 0x80, 0x5a, 0x34, 0x25, 0x7b, 0xde, 0x55, 0x6c, 0x22, 0x9a, 0xcd, 0x30, 0x46, 0xee, 0x71,
	0xdf, 0xbb, 0x40, 0xbd, 0x55, 0xb8, 0x8c, 0x27, 0x0f, 0xf3, 0xe9, 0x7c, 0x32, 0x76, 0x4f, 0xbc,
	0x1e, 0x3a, 0x5b, 0x85, 0x8f, 0x61, 0xf4, 0x12, 0xba, 0x1d, 0xef, 0x1c, 0x21, 0x1a, 0x8e, 0xd3,
	0x68, 0x9a, 0x46, 0x8b, 0xa5, 0xeb, 0xe8, 0x3a, 0x5a, 0xe8, 0x92, 0x86, 0xe3, 0xa5, 0xdb, 0x1d,
	0xed, 0x3b, 0x68, 0xf0, 0x2e, 0x37, 0xf8, 0xdf, 0xb4, 0xa3, 0xab, 0xe3, 0x5f, 0x63, 0x1d, 0x33,
	0xee, 0xbc, 0x8e, 0x7e, 0x7d, 0x5c, 0x96, 0x99, 0xe0, 0x58, 0xd6, 0xdc, 0xe7, 0x4c, 0x98, 0x25,
	0x0e, 0xe7, 0xaa, 0x0a, 0xf8, 0xe3, 0x7a, 0xf7, 0xe6, 0xfd, 0x74, 0xba, 0x33, 0x4a, 0xbf, 0x9c,
	0xfe, 0xcc, 0x8e, 0xa2, 0x39, 0x60, 0x0b, 0x35, 0x5a, 0x07, 0x58, 0x6f, 0x0e, 0xdf, 0x07, 0x3e,
	0xa1, 0x39, 0x24, 0x2d, 0x9f, 0xac, 0x83, 0xc4, 0xf0, 0x7b, 0x67, 0x60, 0x9b, 0x84, 0xd0, 0x1c,
	0x08, 0x69, 0x15, 0x84, 0xac, 0x03, 0x42, 0x8c, 0xe6, 0xed, 0xd4, 0x04, 0xbb, 0xfd, 0x09, 0x00,
	0x00, 0xff, 0xff, 0xab, 0x46, 0xd8, 0xca, 0xd5, 0x01, 0x00, 0x00,
}
