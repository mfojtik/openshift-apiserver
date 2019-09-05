// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/cloud/vision/v1/web_detection.proto

package vision // import "google.golang.org/genproto/googleapis/cloud/vision/v1"

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

// Relevant information for the image from the Internet.
type WebDetection struct {
	// Deduced entities from similar images on the Internet.
	WebEntities []*WebDetection_WebEntity `protobuf:"bytes,1,rep,name=web_entities,json=webEntities,proto3" json:"web_entities,omitempty"`
	// Fully matching images from the Internet.
	// Can include resized copies of the query image.
	FullMatchingImages []*WebDetection_WebImage `protobuf:"bytes,2,rep,name=full_matching_images,json=fullMatchingImages,proto3" json:"full_matching_images,omitempty"`
	// Partial matching images from the Internet.
	// Those images are similar enough to share some key-point features. For
	// example an original image will likely have partial matching for its crops.
	PartialMatchingImages []*WebDetection_WebImage `protobuf:"bytes,3,rep,name=partial_matching_images,json=partialMatchingImages,proto3" json:"partial_matching_images,omitempty"`
	// Web pages containing the matching images from the Internet.
	PagesWithMatchingImages []*WebDetection_WebPage `protobuf:"bytes,4,rep,name=pages_with_matching_images,json=pagesWithMatchingImages,proto3" json:"pages_with_matching_images,omitempty"`
	// The visually similar image results.
	VisuallySimilarImages []*WebDetection_WebImage `protobuf:"bytes,6,rep,name=visually_similar_images,json=visuallySimilarImages,proto3" json:"visually_similar_images,omitempty"`
	// The service's best guess as to the topic of the request image.
	// Inferred from similar images on the open web.
	BestGuessLabels      []*WebDetection_WebLabel `protobuf:"bytes,8,rep,name=best_guess_labels,json=bestGuessLabels,proto3" json:"best_guess_labels,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *WebDetection) Reset()         { *m = WebDetection{} }
func (m *WebDetection) String() string { return proto.CompactTextString(m) }
func (*WebDetection) ProtoMessage()    {}
func (*WebDetection) Descriptor() ([]byte, []int) {
	return fileDescriptor_web_detection_5b9f638086911196, []int{0}
}
func (m *WebDetection) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WebDetection.Unmarshal(m, b)
}
func (m *WebDetection) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WebDetection.Marshal(b, m, deterministic)
}
func (dst *WebDetection) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WebDetection.Merge(dst, src)
}
func (m *WebDetection) XXX_Size() int {
	return xxx_messageInfo_WebDetection.Size(m)
}
func (m *WebDetection) XXX_DiscardUnknown() {
	xxx_messageInfo_WebDetection.DiscardUnknown(m)
}

var xxx_messageInfo_WebDetection proto.InternalMessageInfo

func (m *WebDetection) GetWebEntities() []*WebDetection_WebEntity {
	if m != nil {
		return m.WebEntities
	}
	return nil
}

func (m *WebDetection) GetFullMatchingImages() []*WebDetection_WebImage {
	if m != nil {
		return m.FullMatchingImages
	}
	return nil
}

func (m *WebDetection) GetPartialMatchingImages() []*WebDetection_WebImage {
	if m != nil {
		return m.PartialMatchingImages
	}
	return nil
}

func (m *WebDetection) GetPagesWithMatchingImages() []*WebDetection_WebPage {
	if m != nil {
		return m.PagesWithMatchingImages
	}
	return nil
}

func (m *WebDetection) GetVisuallySimilarImages() []*WebDetection_WebImage {
	if m != nil {
		return m.VisuallySimilarImages
	}
	return nil
}

func (m *WebDetection) GetBestGuessLabels() []*WebDetection_WebLabel {
	if m != nil {
		return m.BestGuessLabels
	}
	return nil
}

// Entity deduced from similar images on the Internet.
type WebDetection_WebEntity struct {
	// Opaque entity ID.
	EntityId string `protobuf:"bytes,1,opt,name=entity_id,json=entityId,proto3" json:"entity_id,omitempty"`
	// Overall relevancy score for the entity.
	// Not normalized and not comparable across different image queries.
	Score float32 `protobuf:"fixed32,2,opt,name=score,proto3" json:"score,omitempty"`
	// Canonical description of the entity, in English.
	Description          string   `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WebDetection_WebEntity) Reset()         { *m = WebDetection_WebEntity{} }
func (m *WebDetection_WebEntity) String() string { return proto.CompactTextString(m) }
func (*WebDetection_WebEntity) ProtoMessage()    {}
func (*WebDetection_WebEntity) Descriptor() ([]byte, []int) {
	return fileDescriptor_web_detection_5b9f638086911196, []int{0, 0}
}
func (m *WebDetection_WebEntity) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WebDetection_WebEntity.Unmarshal(m, b)
}
func (m *WebDetection_WebEntity) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WebDetection_WebEntity.Marshal(b, m, deterministic)
}
func (dst *WebDetection_WebEntity) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WebDetection_WebEntity.Merge(dst, src)
}
func (m *WebDetection_WebEntity) XXX_Size() int {
	return xxx_messageInfo_WebDetection_WebEntity.Size(m)
}
func (m *WebDetection_WebEntity) XXX_DiscardUnknown() {
	xxx_messageInfo_WebDetection_WebEntity.DiscardUnknown(m)
}

var xxx_messageInfo_WebDetection_WebEntity proto.InternalMessageInfo

func (m *WebDetection_WebEntity) GetEntityId() string {
	if m != nil {
		return m.EntityId
	}
	return ""
}

func (m *WebDetection_WebEntity) GetScore() float32 {
	if m != nil {
		return m.Score
	}
	return 0
}

func (m *WebDetection_WebEntity) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

// Metadata for online images.
type WebDetection_WebImage struct {
	// The result image URL.
	Url string `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	// (Deprecated) Overall relevancy score for the image.
	Score                float32  `protobuf:"fixed32,2,opt,name=score,proto3" json:"score,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WebDetection_WebImage) Reset()         { *m = WebDetection_WebImage{} }
func (m *WebDetection_WebImage) String() string { return proto.CompactTextString(m) }
func (*WebDetection_WebImage) ProtoMessage()    {}
func (*WebDetection_WebImage) Descriptor() ([]byte, []int) {
	return fileDescriptor_web_detection_5b9f638086911196, []int{0, 1}
}
func (m *WebDetection_WebImage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WebDetection_WebImage.Unmarshal(m, b)
}
func (m *WebDetection_WebImage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WebDetection_WebImage.Marshal(b, m, deterministic)
}
func (dst *WebDetection_WebImage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WebDetection_WebImage.Merge(dst, src)
}
func (m *WebDetection_WebImage) XXX_Size() int {
	return xxx_messageInfo_WebDetection_WebImage.Size(m)
}
func (m *WebDetection_WebImage) XXX_DiscardUnknown() {
	xxx_messageInfo_WebDetection_WebImage.DiscardUnknown(m)
}

var xxx_messageInfo_WebDetection_WebImage proto.InternalMessageInfo

func (m *WebDetection_WebImage) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *WebDetection_WebImage) GetScore() float32 {
	if m != nil {
		return m.Score
	}
	return 0
}

// Label to provide extra metadata for the web detection.
type WebDetection_WebLabel struct {
	// Label for extra metadata.
	Label string `protobuf:"bytes,1,opt,name=label,proto3" json:"label,omitempty"`
	// The BCP-47 language code for `label`, such as "en-US" or "sr-Latn".
	// For more information, see
	// http://www.unicode.org/reports/tr35/#Unicode_locale_identifier.
	LanguageCode         string   `protobuf:"bytes,2,opt,name=language_code,json=languageCode,proto3" json:"language_code,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WebDetection_WebLabel) Reset()         { *m = WebDetection_WebLabel{} }
func (m *WebDetection_WebLabel) String() string { return proto.CompactTextString(m) }
func (*WebDetection_WebLabel) ProtoMessage()    {}
func (*WebDetection_WebLabel) Descriptor() ([]byte, []int) {
	return fileDescriptor_web_detection_5b9f638086911196, []int{0, 2}
}
func (m *WebDetection_WebLabel) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WebDetection_WebLabel.Unmarshal(m, b)
}
func (m *WebDetection_WebLabel) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WebDetection_WebLabel.Marshal(b, m, deterministic)
}
func (dst *WebDetection_WebLabel) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WebDetection_WebLabel.Merge(dst, src)
}
func (m *WebDetection_WebLabel) XXX_Size() int {
	return xxx_messageInfo_WebDetection_WebLabel.Size(m)
}
func (m *WebDetection_WebLabel) XXX_DiscardUnknown() {
	xxx_messageInfo_WebDetection_WebLabel.DiscardUnknown(m)
}

var xxx_messageInfo_WebDetection_WebLabel proto.InternalMessageInfo

func (m *WebDetection_WebLabel) GetLabel() string {
	if m != nil {
		return m.Label
	}
	return ""
}

func (m *WebDetection_WebLabel) GetLanguageCode() string {
	if m != nil {
		return m.LanguageCode
	}
	return ""
}

// Metadata for web pages.
type WebDetection_WebPage struct {
	// The result web page URL.
	Url string `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	// (Deprecated) Overall relevancy score for the web page.
	Score float32 `protobuf:"fixed32,2,opt,name=score,proto3" json:"score,omitempty"`
	// Title for the web page, may contain HTML markups.
	PageTitle string `protobuf:"bytes,3,opt,name=page_title,json=pageTitle,proto3" json:"page_title,omitempty"`
	// Fully matching images on the page.
	// Can include resized copies of the query image.
	FullMatchingImages []*WebDetection_WebImage `protobuf:"bytes,4,rep,name=full_matching_images,json=fullMatchingImages,proto3" json:"full_matching_images,omitempty"`
	// Partial matching images on the page.
	// Those images are similar enough to share some key-point features. For
	// example an original image will likely have partial matching for its
	// crops.
	PartialMatchingImages []*WebDetection_WebImage `protobuf:"bytes,5,rep,name=partial_matching_images,json=partialMatchingImages,proto3" json:"partial_matching_images,omitempty"`
	XXX_NoUnkeyedLiteral  struct{}                 `json:"-"`
	XXX_unrecognized      []byte                   `json:"-"`
	XXX_sizecache         int32                    `json:"-"`
}

func (m *WebDetection_WebPage) Reset()         { *m = WebDetection_WebPage{} }
func (m *WebDetection_WebPage) String() string { return proto.CompactTextString(m) }
func (*WebDetection_WebPage) ProtoMessage()    {}
func (*WebDetection_WebPage) Descriptor() ([]byte, []int) {
	return fileDescriptor_web_detection_5b9f638086911196, []int{0, 3}
}
func (m *WebDetection_WebPage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WebDetection_WebPage.Unmarshal(m, b)
}
func (m *WebDetection_WebPage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WebDetection_WebPage.Marshal(b, m, deterministic)
}
func (dst *WebDetection_WebPage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WebDetection_WebPage.Merge(dst, src)
}
func (m *WebDetection_WebPage) XXX_Size() int {
	return xxx_messageInfo_WebDetection_WebPage.Size(m)
}
func (m *WebDetection_WebPage) XXX_DiscardUnknown() {
	xxx_messageInfo_WebDetection_WebPage.DiscardUnknown(m)
}

var xxx_messageInfo_WebDetection_WebPage proto.InternalMessageInfo

func (m *WebDetection_WebPage) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *WebDetection_WebPage) GetScore() float32 {
	if m != nil {
		return m.Score
	}
	return 0
}

func (m *WebDetection_WebPage) GetPageTitle() string {
	if m != nil {
		return m.PageTitle
	}
	return ""
}

func (m *WebDetection_WebPage) GetFullMatchingImages() []*WebDetection_WebImage {
	if m != nil {
		return m.FullMatchingImages
	}
	return nil
}

func (m *WebDetection_WebPage) GetPartialMatchingImages() []*WebDetection_WebImage {
	if m != nil {
		return m.PartialMatchingImages
	}
	return nil
}

func init() {
	proto.RegisterType((*WebDetection)(nil), "google.cloud.vision.v1.WebDetection")
	proto.RegisterType((*WebDetection_WebEntity)(nil), "google.cloud.vision.v1.WebDetection.WebEntity")
	proto.RegisterType((*WebDetection_WebImage)(nil), "google.cloud.vision.v1.WebDetection.WebImage")
	proto.RegisterType((*WebDetection_WebLabel)(nil), "google.cloud.vision.v1.WebDetection.WebLabel")
	proto.RegisterType((*WebDetection_WebPage)(nil), "google.cloud.vision.v1.WebDetection.WebPage")
}

func init() {
	proto.RegisterFile("google/cloud/vision/v1/web_detection.proto", fileDescriptor_web_detection_5b9f638086911196)
}

var fileDescriptor_web_detection_5b9f638086911196 = []byte{
	// 511 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x94, 0xdf, 0x6e, 0xd3, 0x30,
	0x14, 0xc6, 0x95, 0xb6, 0x1b, 0xad, 0x5b, 0x04, 0xb3, 0x06, 0x8b, 0x02, 0x48, 0x15, 0xdc, 0x54,
	0x08, 0x12, 0x6d, 0x5c, 0xc2, 0xd5, 0xc6, 0x34, 0x4d, 0x02, 0x54, 0x02, 0x62, 0x82, 0x1b, 0xe3,
	0x24, 0xc6, 0x3d, 0x92, 0x1b, 0x47, 0xb1, 0xd3, 0xaa, 0x6f, 0xc2, 0x35, 0x0f, 0xc4, 0xf3, 0x70,
	0x89, 0xfc, 0x27, 0xa8, 0x5a, 0x37, 0xa9, 0x4c, 0x88, 0xbb, 0x73, 0x4e, 0xcf, 0xf7, 0xfb, 0x7a,
	0x62, 0xfb, 0xa0, 0xa7, 0x5c, 0x4a, 0x2e, 0x58, 0x92, 0x0b, 0xd9, 0x14, 0xc9, 0x02, 0x14, 0xc8,
	0x32, 0x59, 0x1c, 0x26, 0x4b, 0x96, 0x91, 0x82, 0x69, 0x96, 0x6b, 0x90, 0x65, 0x5c, 0xd5, 0x52,
	0x4b, 0x7c, 0xdf, 0xf5, 0xc6, 0xb6, 0x37, 0x76, 0xbd, 0xf1, 0xe2, 0x30, 0x7a, 0xe8, 0x19, 0xb4,
	0x82, 0x84, 0x96, 0xa5, 0xd4, 0xd4, 0x88, 0x94, 0x53, 0x3d, 0xfe, 0xd9, 0x47, 0xa3, 0x0b, 0x96,
	0xbd, 0x6e, 0x61, 0xf8, 0x3d, 0x1a, 0x19, 0x3a, 0x2b, 0x35, 0x68, 0x60, 0x2a, 0x0c, 0xc6, 0xdd,
	0xc9, 0xf0, 0x28, 0x8e, 0xaf, 0xa6, 0xc7, 0xeb, 0x5a, 0x93, 0x9c, 0x1a, 0xdd, 0x2a, 0x1d, 0x2e,
	0x7d, 0x08, 0x4c, 0x61, 0x82, 0xf6, 0xbf, 0x35, 0x42, 0x90, 0x39, 0xd5, 0xf9, 0x0c, 0x4a, 0x4e,
	0x60, 0x4e, 0x39, 0x53, 0x61, 0xc7, 0xa2, 0x9f, 0x6f, 0x8b, 0x3e, 0x37, 0xaa, 0x14, 0x1b, 0xd4,
	0x5b, 0x4f, 0xb2, 0x25, 0x85, 0x19, 0x3a, 0xa8, 0x68, 0xad, 0x81, 0x6e, 0x7a, 0x74, 0x6f, 0xe2,
	0x71, 0xcf, 0xd3, 0x2e, 0xd9, 0x00, 0x8a, 0x2a, 0x13, 0x90, 0x25, 0xe8, 0xd9, 0x86, 0x53, 0xcf,
	0x3a, 0x3d, 0xdb, 0xd6, 0x69, 0x6a, 0x8c, 0x0e, 0x2c, 0xef, 0x02, 0xf4, 0x6c, 0x73, 0xa2, 0x05,
	0xa8, 0x86, 0x0a, 0xb1, 0x22, 0x0a, 0xe6, 0x20, 0x68, 0xdd, 0xfa, 0xec, 0xde, 0x68, 0xa2, 0x96,
	0xf6, 0xc1, 0xc1, 0xbc, 0xcd, 0x67, 0xb4, 0x97, 0x31, 0xa5, 0x09, 0x6f, 0x98, 0x52, 0x44, 0xd0,
	0x8c, 0x09, 0x15, 0xf6, 0xff, 0xce, 0xe0, 0x8d, 0x51, 0xa5, 0x77, 0x0c, 0xe7, 0xcc, 0x60, 0x6c,
	0xae, 0xa2, 0xaf, 0x68, 0xf0, 0xe7, 0x3a, 0xe0, 0x07, 0x68, 0x60, 0x2f, 0xd4, 0x8a, 0x40, 0x11,
	0x06, 0xe3, 0x60, 0x32, 0x48, 0xfb, 0xae, 0x70, 0x5e, 0xe0, 0x7d, 0xb4, 0xa3, 0x72, 0x59, 0xb3,
	0xb0, 0x33, 0x0e, 0x26, 0x9d, 0xd4, 0x25, 0x78, 0x8c, 0x86, 0x05, 0x53, 0x79, 0x0d, 0x95, 0x31,
	0x0a, 0xbb, 0x56, 0xb4, 0x5e, 0x8a, 0x8e, 0x50, 0xbf, 0x9d, 0x0f, 0xdf, 0x45, 0xdd, 0xa6, 0x16,
	0x1e, 0x6d, 0xc2, 0xab, 0xa9, 0xd1, 0xa9, 0xd5, 0xd8, 0xbf, 0x68, 0x3a, 0xec, 0xc4, 0x5e, 0xe5,
	0x12, 0xfc, 0x04, 0xdd, 0x16, 0xb4, 0xe4, 0x0d, 0xe5, 0x8c, 0xe4, 0xb2, 0x70, 0xfa, 0x41, 0x3a,
	0x6a, 0x8b, 0x27, 0xb2, 0x60, 0xd1, 0xf7, 0x0e, 0xba, 0xe5, 0xcf, 0x70, 0x5b, 0x6b, 0xfc, 0x08,
	0x21, 0x73, 0xda, 0x44, 0x83, 0x16, 0xcc, 0xcf, 0x33, 0x30, 0x95, 0x8f, 0xa6, 0x70, 0xed, 0x23,
	0xe9, 0xfd, 0x87, 0x47, 0xb2, 0xf3, 0xef, 0x1e, 0xc9, 0xf1, 0x0a, 0x45, 0xb9, 0x9c, 0x5f, 0x83,
	0x3a, 0xde, 0x5b, 0x67, 0x4d, 0xcd, 0x06, 0x9a, 0x06, 0x5f, 0x5e, 0xf9, 0x66, 0x2e, 0xcd, 0x47,
	0x8e, 0x65, 0xcd, 0x13, 0xce, 0x4a, 0xbb, 0x9f, 0x12, 0xf7, 0x13, 0xad, 0x40, 0x5d, 0x5e, 0x82,
	0x2f, 0x5d, 0xf4, 0x2b, 0x08, 0x7e, 0x74, 0x7a, 0x67, 0x27, 0x9f, 0xde, 0x65, 0xbb, 0x56, 0xf2,
	0xe2, 0x77, 0x00, 0x00, 0x00, 0xff, 0xff, 0x38, 0x42, 0x3a, 0x04, 0x36, 0x05, 0x00, 0x00,
}
