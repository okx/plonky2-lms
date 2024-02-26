use hbs_lms::Sha256_256;

// This file is testing our implementation against the first testcase of the RFC

#[test]
#[ignore]
fn test() {
    assert!(hbs_lms::verify::<Sha256_256>(MESSAGE, SIGNATURE, PUBLIC_KEY).is_ok());
}

static PUBLIC_KEY: &[u8] = &[
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x61, 0xa5, 0xd5, 0x7d,
    0x37, 0xf5, 0xe4, 0x6b, 0xfb, 0x75, 0x20, 0x80, 0x6b, 0x07, 0xa1, 0xb8, 0x50, 0x65, 0x0e, 0x3b,
    0x31, 0xfe, 0x4a, 0x77, 0x3e, 0xa2, 0x9a, 0x07, 0xf0, 0x9c, 0xf2, 0xea, 0x30, 0xe5, 0x79, 0xf0,
    0xdf, 0x58, 0xef, 0x8e, 0x29, 0x8d, 0xa0, 0x43, 0x4c, 0xb2, 0xb8, 0x78,
];

static MESSAGE: &[u8] = &[
    0x54, 0x68, 0x65, 0x20, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x64,
    0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x55, 0x6e, 0x69, 0x74, 0x65, 0x64, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x20, 0x62, 0x79,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x69, 0x6f,
    0x6e, 0x2c, 0x20, 0x6e, 0x6f, 0x72, 0x20, 0x70, 0x72, 0x6f, 0x68, 0x69, 0x62, 0x69, 0x74, 0x65,
    0x64, 0x20, 0x62, 0x79, 0x20, 0x69, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x73, 0x2c, 0x20, 0x61, 0x72, 0x65, 0x20, 0x72, 0x65, 0x73, 0x65, 0x72,
    0x76, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65,
    0x73, 0x20, 0x72, 0x65, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x6c, 0x79, 0x2c, 0x20,
    0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x65, 0x6f, 0x70, 0x6c, 0x65,
    0x2e, 0x0a,
];

static SIGNATURE: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0xd3, 0x2b, 0x56, 0x67,
    0x1d, 0x7e, 0xb9, 0x88, 0x33, 0xc4, 0x9b, 0x43, 0x3c, 0x27, 0x25, 0x86, 0xbc, 0x4a, 0x1c, 0x8a,
    0x89, 0x70, 0x52, 0x8f, 0xfa, 0x04, 0xb9, 0x66, 0xf9, 0x42, 0x6e, 0xb9, 0x96, 0x5a, 0x25, 0xbf,
    0xd3, 0x7f, 0x19, 0x6b, 0x90, 0x73, 0xf3, 0xd4, 0xa2, 0x32, 0xfe, 0xb6, 0x91, 0x28, 0xec, 0x45,
    0x14, 0x6f, 0x86, 0x29, 0x2f, 0x9d, 0xff, 0x96, 0x10, 0xa7, 0xbf, 0x95, 0xa6, 0x4c, 0x7f, 0x60,
    0xf6, 0x26, 0x1a, 0x62, 0x04, 0x3f, 0x86, 0xc7, 0x03, 0x24, 0xb7, 0x70, 0x7f, 0x5b, 0x4a, 0x8a,
    0x6e, 0x19, 0xc1, 0x14, 0xc7, 0xbe, 0x86, 0x6d, 0x48, 0x87, 0x78, 0xa0, 0xe0, 0x5f, 0xd5, 0xc6,
    0x50, 0x9a, 0x6e, 0x61, 0xd5, 0x59, 0xcf, 0x1a, 0x77, 0xa9, 0x70, 0xde, 0x92, 0x7d, 0x60, 0xc7,
    0x0d, 0x3d, 0xe3, 0x1a, 0x7f, 0xa0, 0x10, 0x09, 0x94, 0xe1, 0x62, 0xa2, 0x58, 0x2e, 0x8f, 0xf1,
    0xb1, 0x0c, 0xd9, 0x9d, 0x4e, 0x8e, 0x41, 0x3e, 0xf4, 0x69, 0x55, 0x9f, 0x7d, 0x7e, 0xd1, 0x2c,
    0x83, 0x83, 0x42, 0xf9, 0xb9, 0xc9, 0x6b, 0x83, 0xa4, 0x94, 0x3d, 0x16, 0x81, 0xd8, 0x4b, 0x15,
    0x35, 0x7f, 0xf4, 0x8c, 0xa5, 0x79, 0xf1, 0x9f, 0x5e, 0x71, 0xf1, 0x84, 0x66, 0xf2, 0xbb, 0xef,
    0x4b, 0xf6, 0x60, 0xc2, 0x51, 0x8e, 0xb2, 0x0d, 0xe2, 0xf6, 0x6e, 0x3b, 0x14, 0x78, 0x42, 0x69,
    0xd7, 0xd8, 0x76, 0xf5, 0xd3, 0x5d, 0x3f, 0xbf, 0xc7, 0x03, 0x9a, 0x46, 0x2c, 0x71, 0x6b, 0xb9,
    0xf6, 0x89, 0x1a, 0x7f, 0x41, 0xad, 0x13, 0x3e, 0x9e, 0x1f, 0x6d, 0x95, 0x60, 0xb9, 0x60, 0xe7,
    0x77, 0x7c, 0x52, 0xf0, 0x60, 0x49, 0x2f, 0x2d, 0x7c, 0x66, 0x0e, 0x14, 0x71, 0xe0, 0x7e, 0x72,
    0x65, 0x55, 0x62, 0x03, 0x5a, 0xbc, 0x9a, 0x70, 0x1b, 0x47, 0x3e, 0xcb, 0xc3, 0x94, 0x3c, 0x6b,
    0x9c, 0x4f, 0x24, 0x05, 0xa3, 0xcb, 0x8b, 0xf8, 0xa6, 0x91, 0xca, 0x51, 0xd3, 0xf6, 0xad, 0x2f,
    0x42, 0x8b, 0xab, 0x6f, 0x3a, 0x30, 0xf5, 0x5d, 0xd9, 0x62, 0x55, 0x63, 0xf0, 0xa7, 0x5e, 0xe3,
    0x90, 0xe3, 0x85, 0xe3, 0xae, 0x0b, 0x90, 0x69, 0x61, 0xec, 0xf4, 0x1a, 0xe0, 0x73, 0xa0, 0x59,
    0x0c, 0x2e, 0xb6, 0x20, 0x4f, 0x44, 0x83, 0x1c, 0x26, 0xdd, 0x76, 0x8c, 0x35, 0xb1, 0x67, 0xb2,
    0x8c, 0xe8, 0xdc, 0x98, 0x8a, 0x37, 0x48, 0x25, 0x52, 0x30, 0xce, 0xf9, 0x9e, 0xbf, 0x14, 0xe7,
    0x30, 0x63, 0x2f, 0x27, 0x41, 0x44, 0x89, 0x80, 0x8a, 0xfa, 0xb1, 0xd1, 0xe7, 0x83, 0xed, 0x04,
    0x51, 0x6d, 0xe0, 0x12, 0x49, 0x86, 0x82, 0x21, 0x2b, 0x07, 0x81, 0x05, 0x79, 0xb2, 0x50, 0x36,
    0x59, 0x41, 0xbc, 0xc9, 0x81, 0x42, 0xda, 0x13, 0x60, 0x9e, 0x97, 0x68, 0xaa, 0xf6, 0x5d, 0xe7,
    0x62, 0x0d, 0xab, 0xec, 0x29, 0xeb, 0x82, 0xa1, 0x7f, 0xde, 0x35, 0xaf, 0x15, 0xad, 0x23, 0x8c,
    0x73, 0xf8, 0x1b, 0xdb, 0x8d, 0xec, 0x2f, 0xc0, 0xe7, 0xf9, 0x32, 0x70, 0x10, 0x99, 0x76, 0x2b,
    0x37, 0xf4, 0x3c, 0x4a, 0x3c, 0x20, 0x01, 0x0a, 0x3d, 0x72, 0xe2, 0xf6, 0x06, 0xbe, 0x10, 0x8d,
    0x31, 0x0e, 0x63, 0x9f, 0x09, 0xce, 0x72, 0x86, 0x80, 0x0d, 0x9e, 0xf8, 0xa1, 0xa4, 0x02, 0x81,
    0xcc, 0x5a, 0x7e, 0xa9, 0x8d, 0x2a, 0xdc, 0x7c, 0x74, 0x00, 0xc2, 0xfe, 0x5a, 0x10, 0x15, 0x52,
    0xdf, 0x4e, 0x3c, 0xcc, 0xfd, 0x0c, 0xbf, 0x2d, 0xdf, 0x5d, 0xc6, 0x77, 0x9c, 0xbb, 0xc6, 0x8f,
    0xee, 0x0c, 0x3e, 0xfe, 0x4e, 0xc2, 0x2b, 0x83, 0xa2, 0xca, 0xa3, 0xe4, 0x8e, 0x08, 0x09, 0xa0,
    0xa7, 0x50, 0xb7, 0x3c, 0xcd, 0xcf, 0x3c, 0x79, 0xe6, 0x58, 0x0c, 0x15, 0x4f, 0x8a, 0x58, 0xf7,
    0xf2, 0x43, 0x35, 0xee, 0xc5, 0xc5, 0xeb, 0x5e, 0x0c, 0xf0, 0x1d, 0xcf, 0x44, 0x39, 0x42, 0x40,
    0x95, 0xfc, 0xeb, 0x07, 0x7f, 0x66, 0xde, 0xd5, 0xbe, 0xc7, 0x3b, 0x27, 0xc5, 0xb9, 0xf6, 0x4a,
    0x2a, 0x9a, 0xf2, 0xf0, 0x7c, 0x05, 0xe9, 0x9e, 0x5c, 0xf8, 0x0f, 0x00, 0x25, 0x2e, 0x39, 0xdb,
    0x32, 0xf6, 0xc1, 0x96, 0x74, 0xf1, 0x90, 0xc9, 0xfb, 0xc5, 0x06, 0xd8, 0x26, 0x85, 0x77, 0x13,
    0xaf, 0xd2, 0xca, 0x6b, 0xb8, 0x5c, 0xd8, 0xc1, 0x07, 0x34, 0x75, 0x52, 0xf3, 0x05, 0x75, 0xa5,
    0x41, 0x78, 0x16, 0xab, 0x4d, 0xb3, 0xf6, 0x03, 0xf2, 0xdf, 0x56, 0xfb, 0xc4, 0x13, 0xe7, 0xd0,
    0xac, 0xd8, 0xbd, 0xd8, 0x13, 0x52, 0xb2, 0x47, 0x1f, 0xc1, 0xbc, 0x4f, 0x1e, 0xf2, 0x96, 0xfe,
    0xa1, 0x22, 0x04, 0x03, 0x46, 0x6b, 0x1a, 0xfe, 0x78, 0xb9, 0x4f, 0x7e, 0xcf, 0x7c, 0xc6, 0x2f,
    0xb9, 0x2b, 0xe1, 0x4f, 0x18, 0xc2, 0x19, 0x23, 0x84, 0xeb, 0xce, 0xaf, 0x88, 0x01, 0xaf, 0xdf,
    0x94, 0x7f, 0x69, 0x8c, 0xe9, 0xc6, 0xce, 0xb6, 0x96, 0xed, 0x70, 0xe9, 0xe8, 0x7b, 0x01, 0x44,
    0x41, 0x7e, 0x8d, 0x7b, 0xaf, 0x25, 0xeb, 0x5f, 0x70, 0xf0, 0x9f, 0x01, 0x6f, 0xc9, 0x25, 0xb4,
    0xdb, 0x04, 0x8a, 0xb8, 0xd8, 0xcb, 0x2a, 0x66, 0x1c, 0xe3, 0xb5, 0x7a, 0xda, 0x67, 0x57, 0x1f,
    0x5d, 0xd5, 0x46, 0xfc, 0x22, 0xcb, 0x1f, 0x97, 0xe0, 0xeb, 0xd1, 0xa6, 0x59, 0x26, 0xb1, 0x23,
    0x4f, 0xd0, 0x4f, 0x17, 0x1c, 0xf4, 0x69, 0xc7, 0x6b, 0x88, 0x4c, 0xf3, 0x11, 0x5c, 0xce, 0x6f,
    0x79, 0x2c, 0xc8, 0x4e, 0x36, 0xda, 0x58, 0x96, 0x0c, 0x5f, 0x1d, 0x76, 0x0f, 0x32, 0xc1, 0x2f,
    0xae, 0xf4, 0x77, 0xe9, 0x4c, 0x92, 0xeb, 0x75, 0x62, 0x5b, 0x6a, 0x37, 0x1e, 0xfc, 0x72, 0xd6,
    0x0c, 0xa5, 0xe9, 0x08, 0xb3, 0xa7, 0xdd, 0x69, 0xfe, 0xf0, 0x24, 0x91, 0x50, 0xe3, 0xee, 0xbd,
    0xfe, 0xd3, 0x9c, 0xbd, 0xc3, 0xce, 0x97, 0x04, 0x88, 0x2a, 0x20, 0x72, 0xc7, 0x5e, 0x13, 0x52,
    0x7b, 0x7a, 0x58, 0x1a, 0x55, 0x61, 0x68, 0x78, 0x3d, 0xc1, 0xe9, 0x75, 0x45, 0xe3, 0x18, 0x65,
    0xdd, 0xc4, 0x6b, 0x3c, 0x95, 0x78, 0x35, 0xda, 0x25, 0x2b, 0xb7, 0x32, 0x8d, 0x3e, 0xe2, 0x06,
    0x24, 0x45, 0xdf, 0xb8, 0x5e, 0xf8, 0xc3, 0x5f, 0x8e, 0x1f, 0x33, 0x71, 0xaf, 0x34, 0x02, 0x3c,
    0xef, 0x62, 0x6e, 0x0a, 0xf1, 0xe0, 0xbc, 0x01, 0x73, 0x51, 0xaa, 0xe2, 0xab, 0x8f, 0x5c, 0x61,
    0x2e, 0xad, 0x0b, 0x72, 0x9a, 0x1d, 0x05, 0x9d, 0x02, 0xbf, 0xe1, 0x8e, 0xfa, 0x97, 0x1b, 0x73,
    0x00, 0xe8, 0x82, 0x36, 0x0a, 0x93, 0xb0, 0x25, 0xff, 0x97, 0xe9, 0xe0, 0xee, 0xc0, 0xf3, 0xf3,
    0xf1, 0x30, 0x39, 0xa1, 0x7f, 0x88, 0xb0, 0xcf, 0x80, 0x8f, 0x48, 0x84, 0x31, 0x60, 0x6c, 0xb1,
    0x3f, 0x92, 0x41, 0xf4, 0x0f, 0x44, 0xe5, 0x37, 0xd3, 0x02, 0xc6, 0x4a, 0x4f, 0x1f, 0x4a, 0xb9,
    0x49, 0xb9, 0xfe, 0xef, 0xad, 0xcb, 0x71, 0xab, 0x50, 0xef, 0x27, 0xd6, 0xd6, 0xca, 0x85, 0x10,
    0xf1, 0x50, 0xc8, 0x5f, 0xb5, 0x25, 0xbf, 0x25, 0x70, 0x3d, 0xf7, 0x20, 0x9b, 0x60, 0x66, 0xf0,
    0x9c, 0x37, 0x28, 0x0d, 0x59, 0x12, 0x8d, 0x2f, 0x0f, 0x63, 0x7c, 0x7d, 0x7d, 0x7f, 0xad, 0x4e,
    0xd1, 0xc1, 0xea, 0x04, 0xe6, 0x28, 0xd2, 0x21, 0xe3, 0xd8, 0xdb, 0x77, 0xb7, 0xc8, 0x78, 0xc9,
    0x41, 0x1c, 0xaf, 0xc5, 0x07, 0x1a, 0x34, 0xa0, 0x0f, 0x4c, 0xf0, 0x77, 0x38, 0x91, 0x27, 0x53,
    0xdf, 0xce, 0x48, 0xf0, 0x75, 0x76, 0xf0, 0xd4, 0xf9, 0x4f, 0x42, 0xc6, 0xd7, 0x6f, 0x7c, 0xe9,
    0x73, 0xe9, 0x36, 0x70, 0x95, 0xba, 0x7e, 0x9a, 0x36, 0x49, 0xb7, 0xf4, 0x61, 0xd9, 0xf9, 0xac,
    0x13, 0x32, 0xa4, 0xd1, 0x04, 0x4c, 0x96, 0xae, 0xfe, 0xe6, 0x76, 0x76, 0x40, 0x1b, 0x64, 0x45,
    0x7c, 0x54, 0xd6, 0x5f, 0xef, 0x65, 0x00, 0xc5, 0x9c, 0xdf, 0xb6, 0x9a, 0xf7, 0xb6, 0xdd, 0xdf,
    0xcb, 0x0f, 0x08, 0x62, 0x78, 0xdd, 0x8a, 0xd0, 0x68, 0x60, 0x78, 0xdf, 0xb0, 0xf3, 0xf7, 0x9c,
    0xd8, 0x93, 0xd3, 0x14, 0x16, 0x86, 0x48, 0x49, 0x98, 0x98, 0xfb, 0xc0, 0xce, 0xd5, 0xf9, 0x5b,
    0x74, 0xe8, 0xff, 0x14, 0xd7, 0x35, 0xcd, 0xea, 0x96, 0x8b, 0xee, 0x74, 0x00, 0x00, 0x00, 0x05,
    0xd8, 0xb8, 0x11, 0x2f, 0x92, 0x00, 0xa5, 0xe5, 0x0c, 0x4a, 0x26, 0x21, 0x65, 0xbd, 0x34, 0x2c,
    0xd8, 0x00, 0xb8, 0x49, 0x68, 0x10, 0xbc, 0x71, 0x62, 0x77, 0x43, 0x5a, 0xc3, 0x76, 0x72, 0x8d,
    0x12, 0x9a, 0xc6, 0xed, 0xa8, 0x39, 0xa6, 0xf3, 0x57, 0xb5, 0xa0, 0x43, 0x87, 0xc5, 0xce, 0x97,
    0x38, 0x2a, 0x78, 0xf2, 0xa4, 0x37, 0x29, 0x17, 0xee, 0xfc, 0xbf, 0x93, 0xf6, 0x3b, 0xb5, 0x91,
    0x12, 0xf5, 0xdb, 0xe4, 0x00, 0xbd, 0x49, 0xe4, 0x50, 0x1e, 0x85, 0x9f, 0x88, 0x5b, 0xf0, 0x73,
    0x6e, 0x90, 0xa5, 0x09, 0xb3, 0x0a, 0x26, 0xbf, 0xac, 0x8c, 0x17, 0xb5, 0x99, 0x1c, 0x15, 0x7e,
    0xb5, 0x97, 0x11, 0x15, 0xaa, 0x39, 0xef, 0xd8, 0xd5, 0x64, 0xa6, 0xb9, 0x02, 0x82, 0xc3, 0x16,
    0x8a, 0xf2, 0xd3, 0x0e, 0xf8, 0x9d, 0x51, 0xbf, 0x14, 0x65, 0x45, 0x10, 0xa1, 0x2b, 0x8a, 0x14,
    0x4c, 0xca, 0x18, 0x48, 0xcf, 0x7d, 0xa5, 0x9c, 0xc2, 0xb3, 0xd9, 0xd0, 0x69, 0x2d, 0xd2, 0xa2,
    0x0b, 0xa3, 0x86, 0x34, 0x80, 0xe2, 0x5b, 0x1b, 0x85, 0xee, 0x86, 0x0c, 0x62, 0xbf, 0x51, 0x36,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0xd2, 0xf1, 0x4f, 0xf6, 0x34, 0x6a, 0xf9, 0x64,
    0x56, 0x9f, 0x7d, 0x6c, 0xb8, 0x80, 0xa1, 0xb6, 0x6c, 0x50, 0x04, 0x91, 0x7d, 0xa6, 0xea, 0xfe,
    0x4d, 0x9e, 0xf6, 0xc6, 0x40, 0x7b, 0x3d, 0xb0, 0xe5, 0x48, 0x5b, 0x12, 0x2d, 0x9e, 0xbe, 0x15,
    0xcd, 0xa9, 0x3c, 0xfe, 0xc5, 0x82, 0xd7, 0xab, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x04,
    0x07, 0x03, 0xc4, 0x91, 0xe7, 0x55, 0x8b, 0x35, 0x01, 0x1e, 0xce, 0x35, 0x92, 0xea, 0xa5, 0xda,
    0x4d, 0x91, 0x87, 0x86, 0x77, 0x12, 0x33, 0xe8, 0x35, 0x3b, 0xc4, 0xf6, 0x23, 0x23, 0x18, 0x5c,
    0x95, 0xca, 0xe0, 0x5b, 0x89, 0x9e, 0x35, 0xdf, 0xfd, 0x71, 0x70, 0x54, 0x70, 0x62, 0x09, 0x98,
    0x8e, 0xbf, 0xdf, 0x6e, 0x37, 0x96, 0x0b, 0xb5, 0xc3, 0x8d, 0x76, 0x57, 0xe8, 0xbf, 0xfe, 0xef,
    0x9b, 0xc0, 0x42, 0xda, 0x4b, 0x45, 0x25, 0x65, 0x04, 0x85, 0xc6, 0x6d, 0x0c, 0xe1, 0x9b, 0x31,
    0x75, 0x87, 0xc6, 0xba, 0x4b, 0xff, 0xcc, 0x42, 0x8e, 0x25, 0xd0, 0x89, 0x31, 0xe7, 0x2d, 0xfb,
    0x6a, 0x12, 0x0c, 0x56, 0x12, 0x34, 0x42, 0x58, 0xb8, 0x5e, 0xfd, 0xb7, 0xdb, 0x1d, 0xb9, 0xe1,
    0x86, 0x5a, 0x73, 0xca, 0xf9, 0x65, 0x57, 0xeb, 0x39, 0xed, 0x3e, 0x3f, 0x42, 0x69, 0x33, 0xac,
    0x9e, 0xed, 0xdb, 0x03, 0xa1, 0xd2, 0x37, 0x4a, 0xf7, 0xbf, 0x77, 0x18, 0x55, 0x77, 0x45, 0x62,
    0x37, 0xf9, 0xde, 0x2d, 0x60, 0x11, 0x3c, 0x23, 0xf8, 0x46, 0xdf, 0x26, 0xfa, 0x94, 0x20, 0x08,
    0xa6, 0x98, 0x99, 0x4c, 0x08, 0x27, 0xd9, 0x0e, 0x86, 0xd4, 0x3e, 0x0d, 0xf7, 0xf4, 0xbf, 0xcd,
    0xb0, 0x9b, 0x86, 0xa3, 0x73, 0xb9, 0x82, 0x88, 0xb7, 0x09, 0x4a, 0xd8, 0x1a, 0x01, 0x85, 0xac,
    0x10, 0x0e, 0x4f, 0x2c, 0x5f, 0xc3, 0x8c, 0x00, 0x3c, 0x1a, 0xb6, 0xfe, 0xa4, 0x79, 0xeb, 0x2f,
    0x5e, 0xbe, 0x48, 0xf5, 0x84, 0xd7, 0x15, 0x9b, 0x8a, 0xda, 0x03, 0x58, 0x6e, 0x65, 0xad, 0x9c,
    0x96, 0x9f, 0x6a, 0xec, 0xbf, 0xe4, 0x4c, 0xf3, 0x56, 0x88, 0x8a, 0x7b, 0x15, 0xa3, 0xff, 0x07,
    0x4f, 0x77, 0x17, 0x60, 0xb2, 0x6f, 0x9c, 0x04, 0x88, 0x4e, 0xe1, 0xfa, 0xa3, 0x29, 0xfb, 0xf4,
    0xe6, 0x1a, 0xf2, 0x3a, 0xee, 0x7f, 0xa5, 0xd4, 0xd9, 0xa5, 0xdf, 0xcf, 0x43, 0xc4, 0xc2, 0x6c,
    0xe8, 0xae, 0xa2, 0xce, 0x8a, 0x29, 0x90, 0xd7, 0xba, 0x7b, 0x57, 0x10, 0x8b, 0x47, 0xda, 0xbf,
    0xbe, 0xad, 0xb2, 0xb2, 0x5b, 0x3c, 0xac, 0xc1, 0xac, 0x0c, 0xef, 0x34, 0x6c, 0xbb, 0x90, 0xfb,
    0x04, 0x4b, 0xee, 0xe4, 0xfa, 0xc2, 0x60, 0x3a, 0x44, 0x2b, 0xdf, 0x7e, 0x50, 0x72, 0x43, 0xb7,
    0x31, 0x9c, 0x99, 0x44, 0xb1, 0x58, 0x6e, 0x89, 0x9d, 0x43, 0x1c, 0x7f, 0x91, 0xbc, 0xcc, 0xc8,
    0x69, 0x0d, 0xbf, 0x59, 0xb2, 0x83, 0x86, 0xb2, 0x31, 0x5f, 0x3d, 0x36, 0xef, 0x2e, 0xaa, 0x3c,
    0xf3, 0x0b, 0x2b, 0x51, 0xf4, 0x8b, 0x71, 0xb0, 0x03, 0xdf, 0xb0, 0x82, 0x49, 0x48, 0x42, 0x01,
    0x04, 0x3f, 0x65, 0xf5, 0xa3, 0xef, 0x6b, 0xbd, 0x61, 0xdd, 0xfe, 0xe8, 0x1a, 0xca, 0x9c, 0xe6,
    0x00, 0x81, 0x26, 0x2a, 0x00, 0x00, 0x04, 0x80, 0xdc, 0xbc, 0x9a, 0x3d, 0xa6, 0xfb, 0xef, 0x5c,
    0x1c, 0x0a, 0x55, 0xe4, 0x8a, 0x0e, 0x72, 0x9f, 0x91, 0x84, 0xfc, 0xb1, 0x40, 0x7c, 0x31, 0x52,
    0x9d, 0xb2, 0x68, 0xf6, 0xfe, 0x50, 0x03, 0x2a, 0x36, 0x3c, 0x98, 0x01, 0x30, 0x68, 0x37, 0xfa,
    0xfa, 0xbd, 0xf9, 0x57, 0xfd, 0x97, 0xea, 0xfc, 0x80, 0xdb, 0xd1, 0x65, 0xe4, 0x35, 0xd0, 0xe2,
    0xdf, 0xd8, 0x36, 0xa2, 0x8b, 0x35, 0x40, 0x23, 0x92, 0x4b, 0x6f, 0xb7, 0xe4, 0x8b, 0xc0, 0xb3,
    0xed, 0x95, 0xee, 0xa6, 0x4c, 0x2d, 0x40, 0x2f, 0x4d, 0x73, 0x4c, 0x8d, 0xc2, 0x6f, 0x3a, 0xc5,
    0x91, 0x82, 0x5d, 0xae, 0xf0, 0x1e, 0xae, 0x3c, 0x38, 0xe3, 0x32, 0x8d, 0x00, 0xa7, 0x7d, 0xc6,
    0x57, 0x03, 0x4f, 0x28, 0x7c, 0xcb, 0x0f, 0x0e, 0x1c, 0x9a, 0x7c, 0xbd, 0xc8, 0x28, 0xf6, 0x27,
    0x20, 0x5e, 0x47, 0x37, 0xb8, 0x4b, 0x58, 0x37, 0x65, 0x51, 0xd4, 0x4c, 0x12, 0xc3, 0xc2, 0x15,
    0xc8, 0x12, 0xa0, 0x97, 0x07, 0x89, 0xc8, 0x3d, 0xe5, 0x1d, 0x6a, 0xd7, 0x87, 0x27, 0x19, 0x63,
    0x32, 0x7f, 0x0a, 0x5f, 0xbb, 0x6b, 0x59, 0x07, 0xde, 0xc0, 0x2c, 0x9a, 0x90, 0x93, 0x4a, 0xf5,
    0xa1, 0xc6, 0x3b, 0x72, 0xc8, 0x26, 0x53, 0x60, 0x5d, 0x1d, 0xcc, 0xe5, 0x15, 0x96, 0xb3, 0xc2,
    0xb4, 0x56, 0x96, 0x68, 0x9f, 0x2e, 0xb3, 0x82, 0x00, 0x74, 0x97, 0x55, 0x76, 0x92, 0xca, 0xac,
    0x4d, 0x57, 0xb5, 0xde, 0x9f, 0x55, 0x69, 0xbc, 0x2a, 0xd0, 0x13, 0x7f, 0xd4, 0x7f, 0xb4, 0x7e,
    0x66, 0x4f, 0xcb, 0x6d, 0xb4, 0x97, 0x1f, 0x5b, 0x3e, 0x07, 0xac, 0xed, 0xa9, 0xac, 0x13, 0x0e,
    0x9f, 0x38, 0x18, 0x2d, 0xe9, 0x94, 0xcf, 0xf1, 0x92, 0xec, 0x0e, 0x82, 0xfd, 0x6d, 0x4c, 0xb7,
    0xf3, 0xfe, 0x00, 0x81, 0x25, 0x89, 0xb7, 0xa7, 0xce, 0x51, 0x54, 0x40, 0x45, 0x64, 0x33, 0x01,
    0x6b, 0x84, 0xa5, 0x9b, 0xec, 0x66, 0x19, 0xa1, 0xc6, 0xc0, 0xb3, 0x7d, 0xd1, 0x45, 0x0e, 0xd4,
    0xf2, 0xd8, 0xb5, 0x84, 0x41, 0x0c, 0xed, 0xa8, 0x02, 0x5f, 0x5d, 0x2d, 0x8d, 0xd0, 0xd2, 0x17,
    0x6f, 0xc1, 0xcf, 0x2c, 0xc0, 0x6f, 0xa8, 0xc8, 0x2b, 0xed, 0x4d, 0x94, 0x4e, 0x71, 0x33, 0x9e,
    0xce, 0x78, 0x0f, 0xd0, 0x25, 0xbd, 0x41, 0xec, 0x34, 0xeb, 0xff, 0x9d, 0x42, 0x70, 0xa3, 0x22,
    0x4e, 0x01, 0x9f, 0xcb, 0x44, 0x44, 0x74, 0xd4, 0x82, 0xfd, 0x2d, 0xbe, 0x75, 0xef, 0xb2, 0x03,
    0x89, 0xcc, 0x10, 0xcd, 0x60, 0x0a, 0xbb, 0x54, 0xc4, 0x7e, 0xde, 0x93, 0xe0, 0x8c, 0x11, 0x4e,
    0xdb, 0x04, 0x11, 0x7d, 0x71, 0x4d, 0xc1, 0xd5, 0x25, 0xe1, 0x1b, 0xed, 0x87, 0x56, 0x19, 0x2f,
    0x92, 0x9d, 0x15, 0x46, 0x2b, 0x93, 0x9f, 0xf3, 0xf5, 0x2f, 0x22, 0x52, 0xda, 0x2e, 0xd6, 0x4d,
    0x8f, 0xae, 0x88, 0x81, 0x8b, 0x1e, 0xfa, 0x2c, 0x7b, 0x08, 0xc8, 0x79, 0x4f, 0xb1, 0xb2, 0x14,
    0xaa, 0x23, 0x3d, 0xb3, 0x16, 0x28, 0x33, 0x14, 0x1e, 0xa4, 0x38, 0x3f, 0x1a, 0x6f, 0x12, 0x0b,
    0xe1, 0xdb, 0x82, 0xce, 0x36, 0x30, 0xb3, 0x42, 0x91, 0x14, 0x46, 0x31, 0x57, 0xa6, 0x4e, 0x91,
    0x23, 0x4d, 0x47, 0x5e, 0x2f, 0x79, 0xcb, 0xf0, 0x5e, 0x4d, 0xb6, 0xa9, 0x40, 0x7d, 0x72, 0xc6,
    0xbf, 0xf7, 0xd1, 0x19, 0x8b, 0x5c, 0x4d, 0x6a, 0xad, 0x28, 0x31, 0xdb, 0x61, 0x27, 0x49, 0x93,
    0x71, 0x5a, 0x01, 0x82, 0xc7, 0xdc, 0x80, 0x89, 0xe3, 0x2c, 0x85, 0x31, 0xde, 0xed, 0x4f, 0x74,
    0x31, 0xc0, 0x7c, 0x02, 0x19, 0x5e, 0xba, 0x2e, 0xf9, 0x1e, 0xfb, 0x56, 0x13, 0xc3, 0x7a, 0xf7,
    0xae, 0x0c, 0x06, 0x6b, 0xab, 0xc6, 0x93, 0x69, 0x70, 0x0e, 0x1d, 0xd2, 0x6e, 0xdd, 0xc0, 0xd2,
    0x16, 0xc7, 0x81, 0xd5, 0x6e, 0x4c, 0xe4, 0x7e, 0x33, 0x03, 0xfa, 0x73, 0x00, 0x7f, 0xf7, 0xb9,
    0x49, 0xef, 0x23, 0xbe, 0x2a, 0xa4, 0xdb, 0xf2, 0x52, 0x06, 0xfe, 0x45, 0xc2, 0x0d, 0xd8, 0x88,
    0x39, 0x5b, 0x25, 0x26, 0x39, 0x1a, 0x72, 0x49, 0x96, 0xa4, 0x41, 0x56, 0xbe, 0xac, 0x80, 0x82,
    0x12, 0x85, 0x87, 0x92, 0xbf, 0x8e, 0x74, 0xcb, 0xa4, 0x9d, 0xee, 0x5e, 0x88, 0x12, 0xe0, 0x19,
    0xda, 0x87, 0x45, 0x4b, 0xff, 0x9e, 0x84, 0x7e, 0xd8, 0x3d, 0xb0, 0x7a, 0xf3, 0x13, 0x74, 0x30,
    0x82, 0xf8, 0x80, 0xa2, 0x78, 0xf6, 0x82, 0xc2, 0xbd, 0x0a, 0xd6, 0x88, 0x7c, 0xb5, 0x9f, 0x65,
    0x2e, 0x15, 0x59, 0x87, 0xd6, 0x1b, 0xbf, 0x6a, 0x88, 0xd3, 0x6e, 0xe9, 0x3b, 0x60, 0x72, 0xe6,
    0x65, 0x6d, 0x9c, 0xcb, 0xaa, 0xe3, 0xd6, 0x55, 0x85, 0x2e, 0x38, 0xde, 0xb3, 0xa2, 0xdc, 0xf8,
    0x05, 0x8d, 0xc9, 0xfb, 0x6f, 0x2a, 0xb3, 0xd3, 0xb3, 0x53, 0x9e, 0xb7, 0x7b, 0x24, 0x8a, 0x66,
    0x10, 0x91, 0xd0, 0x5e, 0xb6, 0xe2, 0xf2, 0x97, 0x77, 0x4f, 0xe6, 0x05, 0x35, 0x98, 0x45, 0x7c,
    0xc6, 0x19, 0x08, 0x31, 0x8d, 0xe4, 0xb8, 0x26, 0xf0, 0xfc, 0x86, 0xd4, 0xbb, 0x11, 0x7d, 0x33,
    0xe8, 0x65, 0xaa, 0x80, 0x50, 0x09, 0xcc, 0x29, 0x18, 0xd9, 0xc2, 0xf8, 0x40, 0xc4, 0xda, 0x43,
    0xa7, 0x03, 0xad, 0x9f, 0x5b, 0x58, 0x06, 0x16, 0x3d, 0x71, 0x61, 0x69, 0x6b, 0x5a, 0x0a, 0xdc,
    0x00, 0x00, 0x00, 0x05, 0xd5, 0xc0, 0xd1, 0xbe, 0xbb, 0x06, 0x04, 0x8e, 0xd6, 0xfe, 0x2e, 0xf2,
    0xc6, 0xce, 0xf3, 0x05, 0xb3, 0xed, 0x63, 0x39, 0x41, 0xeb, 0xc8, 0xb3, 0xbe, 0xc9, 0x73, 0x87,
    0x54, 0xcd, 0xdd, 0x60, 0xe1, 0x92, 0x0a, 0xda, 0x52, 0xf4, 0x3d, 0x05, 0x5b, 0x50, 0x31, 0xce,
    0xe6, 0x19, 0x25, 0x20, 0xd6, 0xa5, 0x11, 0x55, 0x14, 0x85, 0x1c, 0xe7, 0xfd, 0x44, 0x8d, 0x4a,
    0x39, 0xfa, 0xe2, 0xab, 0x23, 0x35, 0xb5, 0x25, 0xf4, 0x84, 0xe9, 0xb4, 0x0d, 0x6a, 0x4a, 0x96,
    0x93, 0x94, 0x84, 0x3b, 0xdc, 0xf6, 0xd1, 0x4c, 0x48, 0xe8, 0x01, 0x5e, 0x08, 0xab, 0x92, 0x66,
    0x2c, 0x05, 0xc6, 0xe9, 0xf9, 0x0b, 0x65, 0xa7, 0xa6, 0x20, 0x16, 0x89, 0x99, 0x9f, 0x32, 0xbf,
    0xd3, 0x68, 0xe5, 0xe3, 0xec, 0x9c, 0xb7, 0x0a, 0xc7, 0xb8, 0x39, 0x90, 0x03, 0xf1, 0x75, 0xc4,
    0x08, 0x85, 0x08, 0x1a, 0x09, 0xab, 0x30, 0x34, 0x91, 0x1f, 0xe1, 0x25, 0x63, 0x10, 0x51, 0xdf,
    0x04, 0x08, 0xb3, 0x94, 0x6b, 0x0b, 0xde, 0x79, 0x09, 0x11, 0xe8, 0x97, 0x8b, 0xa0, 0x7d, 0xd5,
    0x6c, 0x73, 0xe7, 0xee,
];
