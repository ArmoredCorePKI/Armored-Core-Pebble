// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.6.1
// source: pentry.proto

package trclient

import (
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

type PUFEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Caname string `protobuf:"bytes,1,opt,name=caname,proto3" json:"caname,omitempty"`
	Manu   string `protobuf:"bytes,2,opt,name=manu,proto3" json:"manu,omitempty"`
	Ts     []byte `protobuf:"bytes,3,opt,name=ts,proto3" json:"ts,omitempty"`
	Pufid  []byte `protobuf:"bytes,4,opt,name=pufid,proto3" json:"pufid,omitempty"`
	Comrp  []byte `protobuf:"bytes,5,opt,name=comrp,proto3" json:"comrp,omitempty"`
	Tag    []byte `protobuf:"bytes,6,opt,name=tag,proto3" json:"tag,omitempty"`
}

func (x *PUFEntry) Reset() {
	*x = PUFEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pentry_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PUFEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PUFEntry) ProtoMessage() {}

func (x *PUFEntry) ProtoReflect() protoreflect.Message {
	mi := &file_pentry_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PUFEntry.ProtoReflect.Descriptor instead.
func (*PUFEntry) Descriptor() ([]byte, []int) {
	return file_pentry_proto_rawDescGZIP(), []int{0}
}

func (x *PUFEntry) GetCaname() string {
	if x != nil {
		return x.Caname
	}
	return ""
}

func (x *PUFEntry) GetManu() string {
	if x != nil {
		return x.Manu
	}
	return ""
}

func (x *PUFEntry) GetTs() []byte {
	if x != nil {
		return x.Ts
	}
	return nil
}

func (x *PUFEntry) GetPufid() []byte {
	if x != nil {
		return x.Pufid
	}
	return nil
}

func (x *PUFEntry) GetComrp() []byte {
	if x != nil {
		return x.Comrp
	}
	return nil
}

func (x *PUFEntry) GetTag() []byte {
	if x != nil {
		return x.Tag
	}
	return nil
}

var File_pentry_proto protoreflect.FileDescriptor

var file_pentry_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x70, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x84,
	0x01, 0x0a, 0x08, 0x50, 0x55, 0x46, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x63,
	0x61, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x61, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6d, 0x61, 0x6e, 0x75, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6d, 0x61, 0x6e, 0x75, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x73, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x02, 0x74, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x75, 0x66, 0x69, 0x64,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x70, 0x75, 0x66, 0x69, 0x64, 0x12, 0x14, 0x0a,
	0x05, 0x63, 0x6f, 0x6d, 0x72, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x63, 0x6f,
	0x6d, 0x72, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x61, 0x67, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x03, 0x74, 0x61, 0x67, 0x42, 0x0c, 0x5a, 0x0a, 0x2e, 0x3b, 0x74, 0x72, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pentry_proto_rawDescOnce sync.Once
	file_pentry_proto_rawDescData = file_pentry_proto_rawDesc
)

func file_pentry_proto_rawDescGZIP() []byte {
	file_pentry_proto_rawDescOnce.Do(func() {
		file_pentry_proto_rawDescData = protoimpl.X.CompressGZIP(file_pentry_proto_rawDescData)
	})
	return file_pentry_proto_rawDescData
}

var file_pentry_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_pentry_proto_goTypes = []interface{}{
	(*PUFEntry)(nil), // 0: PUFEntry
}
var file_pentry_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_pentry_proto_init() }
func file_pentry_proto_init() {
	if File_pentry_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pentry_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PUFEntry); i {
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
			RawDescriptor: file_pentry_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pentry_proto_goTypes,
		DependencyIndexes: file_pentry_proto_depIdxs,
		MessageInfos:      file_pentry_proto_msgTypes,
	}.Build()
	File_pentry_proto = out.File
	file_pentry_proto_rawDesc = nil
	file_pentry_proto_goTypes = nil
	file_pentry_proto_depIdxs = nil
}