//! See https://github.com/mcu-tools/mcuboot/blob/main/boot/bootutil/include/bootutil/image.h for more details on these constants.

pub(super) const IMAGE_MAGIC: u32 = 0x96f3b83d;
pub(super) const IMAGE_TLV_INFO_MAGIC: u16 = 0x6907;
pub(super) const IMAGE_TLV_PROT_INFO_MAGIC: u16 = 0x6908;

bitflags::bitflags! {

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ImageHeaderFlags: u32 {
        /// Not supported
        const IMAGE_F_PIC = 0x00000001;
        /// Encrypted using AES128
        const IMAGE_F_ENCRYPTED_AES128 = 0x00000004;
        /// Encrypted using AES256
        const IMAGE_F_ENCRYPTED_AES256 = 0x00000008;
        /// Split image app
        const IMAGE_F_NON_BOOTABLE = 0x00000010;
        /// Indicates that this image should be loaded into RAM instead of run
        /// directly from flash.  The address to load should be in the
        /// ih_load_addr field of the header.
        const IMAGE_F_RAM_LOAD = 0x00000020;
        /// Indicates that ih_load_addr stores information on flash/ROM address the
        /// image has been built for
        const IMAGE_F_ROM_FIXED = 0x00000040;
        /// Flags that indicate if the image data is compressed
        const IMAGE_F_COMPRESSED_LZMA1 = 0x00000200;
        /// Flags that indicate if the image data is compressed
        const IMAGE_F_COMPRESSED_LZMA2 = 0x00000400;
        /// Flags that indicate if the image data is compressed
        const IMAGE_F_COMPRESSED_ARM_THUMB_FLT = 0x00000800;
    }
}

/// hash of the public key
pub(super) const IMAGE_TLV_KEYHASH: u16 = 0x01;
/// public key
pub(super) const IMAGE_TLV_PUBKEY: u16 = 0x02;
/// SHA256 of image hdr and body
pub(super) const IMAGE_TLV_SHA256: u16 = 0x10;
/// SHA384 of image hdr and body
pub(super) const IMAGE_TLV_SHA384: u16 = 0x11;
/// SHA512 of image hdr and body
pub(super) const IMAGE_TLV_SHA512: u16 = 0x12;
/// RSA2048 of hash output
pub(super) const IMAGE_TLV_RSA2048_PSS: u16 = 0x20;
/// ECDSA of hash output - Not supported anymore
pub(super) const IMAGE_TLV_ECDSA224: u16 = 0x21;
/// ECDSA of hash output
pub(super) const IMAGE_TLV_ECDSA_SIG: u16 = 0x22;
/// RSA3072 of hash output
pub(super) const IMAGE_TLV_RSA3072_PSS: u16 = 0x23;
/// ed25519 of hash output
pub(super) const IMAGE_TLV_ED25519: u16 = 0x24;
/// Indicator that attached signature has been prepared
/// over image rather than its digest.
pub(super) const IMAGE_TLV_SIG_PURE: u16 = 0x25;
/// Key encrypted with RSA-OAEP-2048
pub(super) const IMAGE_TLV_ENC_RSA2048: u16 = 0x30;
/// Key encrypted with AES-KW 128 or 256
pub(super) const IMAGE_TLV_ENC_KW: u16 = 0x31;
/// Key encrypted with ECIES-EC256
pub(super) const IMAGE_TLV_ENC_EC256: u16 = 0x32;
/// Key encrypted with ECIES-X25519
pub(super) const IMAGE_TLV_ENC_X25519: u16 = 0x33;
/// Key exchange using ECIES-X25519 and SHA512 for
/// tag and HKDF in key derivation process
pub(super) const IMAGE_TLV_ENC_X25519_SHA512: u16 = 0x34;
/// Image depends on other image
pub(super) const IMAGE_TLV_DEPENDENCY: u16 = 0x40;
/// security counter
pub(super) const IMAGE_TLV_SEC_CNT: u16 = 0x50;
/// measured boot record
/// The following flags relate to compressed images and are for the decompressed image data
pub(super) const IMAGE_TLV_BOOT_RECORD: u16 = 0x60;
/// Decompressed image size excluding header/TLVs
pub(super) const IMAGE_TLV_DECOMP_SIZE: u16 = 0x70;
/// Decompressed image shaX hash, this field must match
/// the format and size of the raw slot (compressed)
/// shaX hash
pub(super) const IMAGE_TLV_DECOMP_SHA: u16 = 0x71;
/// Decompressed image signature, this field must match
/// the format and size of the raw slot (compressed)
/// signature
pub(super) const IMAGE_TLV_DECOMP_SIGNATURE: u16 = 0x72;
/// Compressed decrypted image size
/// vendor reserved TLVs at xxA0-xxFF,
/// where xx denotes the upper byte
/// range.  Examples:
/// 0x00;a0 - 0x00ff
/// 0x01a0 - 0x01ff
/// 0x02a0 - 0x02ff
/// ...
/// 0xffa0 - 0xfffe
pub(super) const IMAGE_TLV_COMP_DEC_SIZE: u16 = 0x73;
/// Vendor unique identifier
pub(super) const IMAGE_TLV_UUID_VID: u16 = 0x80;
/// Device class unique identifier
pub(super) const IMAGE_TLV_UUID_CID: u16 = 0x81;
/// Used to iterate over all TLV
pub(super) const IMAGE_TLV_ANY: u16 = 0xFFFF;
