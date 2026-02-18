//! See https://github.com/mcu-tools/mcuboot/blob/main/boot/bootutil/include/bootutil/image.h for more details on these constants.

use std::io::Cursor;

use crate::mcuboot_constants;

#[derive(Debug, PartialEq)]
pub enum ImageTlvEntryType {
    KeyHash,
    Pubkey,
    Sha256,
    Sha384,
    Sha512,
    Rsa2048Pss,
    Ecdsa224,
    EcdsaSig,
    Rsa3072Pss,
    Ed25519,
    SigPure,
    EncRsa2048,
    EncKw,
    EncEc256,
    EncX25519,
    EncX25519Sha512,
    Dependency,
    SecCnt,
    BootRecord,
    DecompressedSize,
    DecompressedSha,
    DecompressedSignature,
    CompressedDecryptedSize,
    UuidVid,
    UuidCid,
    Any,
    Unknown(u16),
}

impl From<u16> for ImageTlvEntryType {
    fn from(num: u16) -> Self {
        match num {
            mcuboot_constants::IMAGE_TLV_KEYHASH => ImageTlvEntryType::KeyHash,
            mcuboot_constants::IMAGE_TLV_PUBKEY => ImageTlvEntryType::Pubkey,
            mcuboot_constants::IMAGE_TLV_SHA256 => ImageTlvEntryType::Sha256,
            mcuboot_constants::IMAGE_TLV_SHA384 => ImageTlvEntryType::Sha384,
            mcuboot_constants::IMAGE_TLV_SHA512 => ImageTlvEntryType::Sha512,
            mcuboot_constants::IMAGE_TLV_RSA2048_PSS => ImageTlvEntryType::Rsa2048Pss,
            mcuboot_constants::IMAGE_TLV_ECDSA224 => ImageTlvEntryType::Ecdsa224,
            mcuboot_constants::IMAGE_TLV_ECDSA_SIG => ImageTlvEntryType::EcdsaSig,
            mcuboot_constants::IMAGE_TLV_RSA3072_PSS => ImageTlvEntryType::Rsa3072Pss,
            mcuboot_constants::IMAGE_TLV_ED25519 => ImageTlvEntryType::Ed25519,
            mcuboot_constants::IMAGE_TLV_SIG_PURE => ImageTlvEntryType::SigPure,
            mcuboot_constants::IMAGE_TLV_ENC_RSA2048 => ImageTlvEntryType::EncRsa2048,
            mcuboot_constants::IMAGE_TLV_ENC_KW => ImageTlvEntryType::EncKw,
            mcuboot_constants::IMAGE_TLV_ENC_EC256 => ImageTlvEntryType::EncEc256,
            mcuboot_constants::IMAGE_TLV_ENC_X25519 => ImageTlvEntryType::EncX25519,
            mcuboot_constants::IMAGE_TLV_ENC_X25519_SHA512 => ImageTlvEntryType::EncX25519Sha512,
            mcuboot_constants::IMAGE_TLV_DEPENDENCY => ImageTlvEntryType::Dependency,
            mcuboot_constants::IMAGE_TLV_SEC_CNT => ImageTlvEntryType::SecCnt,
            mcuboot_constants::IMAGE_TLV_BOOT_RECORD => ImageTlvEntryType::BootRecord,
            mcuboot_constants::IMAGE_TLV_DECOMP_SIZE => ImageTlvEntryType::DecompressedSize,
            mcuboot_constants::IMAGE_TLV_DECOMP_SHA => ImageTlvEntryType::DecompressedSha,
            mcuboot_constants::IMAGE_TLV_DECOMP_SIGNATURE => {
                ImageTlvEntryType::DecompressedSignature
            }
            mcuboot_constants::IMAGE_TLV_COMP_DEC_SIZE => {
                ImageTlvEntryType::CompressedDecryptedSize
            }
            mcuboot_constants::IMAGE_TLV_UUID_VID => ImageTlvEntryType::UuidVid,
            mcuboot_constants::IMAGE_TLV_UUID_CID => ImageTlvEntryType::UuidCid,
            mcuboot_constants::IMAGE_TLV_ANY => ImageTlvEntryType::Any,
            n => ImageTlvEntryType::Unknown(n),
        }
    }
}

impl From<ImageTlvEntryType> for u16 {
    fn from(tlv: ImageTlvEntryType) -> Self {
        match tlv {
            ImageTlvEntryType::KeyHash => mcuboot_constants::IMAGE_TLV_KEYHASH,
            ImageTlvEntryType::Pubkey => mcuboot_constants::IMAGE_TLV_PUBKEY,
            ImageTlvEntryType::Sha256 => mcuboot_constants::IMAGE_TLV_SHA256,
            ImageTlvEntryType::Sha384 => mcuboot_constants::IMAGE_TLV_SHA384,
            ImageTlvEntryType::Sha512 => mcuboot_constants::IMAGE_TLV_SHA512,
            ImageTlvEntryType::Rsa2048Pss => mcuboot_constants::IMAGE_TLV_RSA2048_PSS,
            ImageTlvEntryType::Ecdsa224 => mcuboot_constants::IMAGE_TLV_ECDSA224,
            ImageTlvEntryType::EcdsaSig => mcuboot_constants::IMAGE_TLV_ECDSA_SIG,
            ImageTlvEntryType::Rsa3072Pss => mcuboot_constants::IMAGE_TLV_RSA3072_PSS,
            ImageTlvEntryType::Ed25519 => mcuboot_constants::IMAGE_TLV_ED25519,
            ImageTlvEntryType::SigPure => mcuboot_constants::IMAGE_TLV_SIG_PURE,
            ImageTlvEntryType::EncRsa2048 => mcuboot_constants::IMAGE_TLV_ENC_RSA2048,
            ImageTlvEntryType::EncKw => mcuboot_constants::IMAGE_TLV_ENC_KW,
            ImageTlvEntryType::EncEc256 => mcuboot_constants::IMAGE_TLV_ENC_EC256,
            ImageTlvEntryType::EncX25519 => mcuboot_constants::IMAGE_TLV_ENC_X25519,
            ImageTlvEntryType::EncX25519Sha512 => mcuboot_constants::IMAGE_TLV_ENC_X25519_SHA512,
            ImageTlvEntryType::Dependency => mcuboot_constants::IMAGE_TLV_DEPENDENCY,
            ImageTlvEntryType::SecCnt => mcuboot_constants::IMAGE_TLV_SEC_CNT,
            ImageTlvEntryType::BootRecord => mcuboot_constants::IMAGE_TLV_BOOT_RECORD,
            ImageTlvEntryType::DecompressedSize => mcuboot_constants::IMAGE_TLV_DECOMP_SIZE,
            ImageTlvEntryType::DecompressedSha => mcuboot_constants::IMAGE_TLV_DECOMP_SHA,
            ImageTlvEntryType::DecompressedSignature => {
                mcuboot_constants::IMAGE_TLV_DECOMP_SIGNATURE
            }
            ImageTlvEntryType::CompressedDecryptedSize => {
                mcuboot_constants::IMAGE_TLV_COMP_DEC_SIZE
            }
            ImageTlvEntryType::UuidVid => mcuboot_constants::IMAGE_TLV_UUID_VID,
            ImageTlvEntryType::UuidCid => mcuboot_constants::IMAGE_TLV_UUID_CID,
            ImageTlvEntryType::Any => mcuboot_constants::IMAGE_TLV_ANY,
            ImageTlvEntryType::Unknown(num) => num,
        }
    }
}

/// Image TLV header.  All fields in little endian
/// Called `image_tlv_info` in mcuboot
#[derive(Debug)]
pub struct ImageTlvAreaHeader {
    /// Can either be `IMAGE_TLV_INFO_MAGIC` or `IMAGE_TLV_PROT_INFO_MAGIC`
    magic: u16,
    /// size of TLV area (including tlv_info header)
    tlv_tot: u16,
}

/// Image trailer TLV format. All fields in little endian
/// Called `image_tlv` in mcuboot
#[derive(Debug)]
pub struct ImageTlvEntry {
    pub type_: ImageTlvEntryType,
    /// Data length (not including TLV header)
    pub len: u16,
    pub value: Vec<u8>,
}

impl TryFrom<&mut Cursor<&[u8]>> for ImageTlvAreaHeader {
    type Error = crate::Error;

    fn try_from(cursor: &mut Cursor<&[u8]>) -> Result<Self, Self::Error> {
        Ok(ImageTlvAreaHeader {
            magic: super::read_u16(cursor)?,
            tlv_tot: super::read_u16(cursor)?,
        })
    }
}

impl TryFrom<&mut Cursor<&[u8]>> for ImageTlvEntry {
    type Error = crate::Error;

    fn try_from(cursor: &mut Cursor<&[u8]>) -> Result<Self, Self::Error> {
        use std::io::Read;
        let type_ = super::read_u16(cursor)?;
        let len = super::read_u16(cursor)?;

        Ok(ImageTlvEntry {
            type_: type_.into(),
            len,
            value: {
                let mut buf = vec![0u8; len as usize];
                cursor
                    .read_exact(&mut buf)
                    .map_err(crate::Error::ImageParsing)?;
                buf
            },
        })
    }
}

pub trait TakeTlvEntry {
    fn take(&mut self, type_: ImageTlvEntryType) -> Result<ImageTlvEntry, crate::Error>;
}
impl TakeTlvEntry for Vec<ImageTlvEntry> {
    fn take(&mut self, type_: ImageTlvEntryType) -> Result<ImageTlvEntry, crate::Error> {
        let index = self.iter().position(|x| x.type_ == type_);

        if let Some(index) = index {
            Ok(self.remove(index))
        } else {
            Err(crate::Error::TlvEntryTypeNotFound(type_.into()))
        }
    }
}

#[derive(Debug)]
pub enum ImageTlvAreaType {
    Protected,
    Unprotected,
    Invalid(u16),
}

impl ImageTlvAreaHeader {
    const HEADER_LEN: u16 = 4;

    pub fn area_type(&self) -> ImageTlvAreaType {
        if self.magic == mcuboot_constants::IMAGE_TLV_INFO_MAGIC {
            ImageTlvAreaType::Unprotected
        } else if self.magic == mcuboot_constants::IMAGE_TLV_PROT_INFO_MAGIC {
            ImageTlvAreaType::Protected
        } else {
            ImageTlvAreaType::Invalid(self.magic)
        }
    }

    pub fn area_size(&self) -> usize {
        self.tlv_tot as usize
    }

    /// Returns the size of the TLV area's payload (i.e. the size of the area excluding the header).
    /// Returns an error if the total size is smaller than the header size.
    pub fn area_payload_size(&self) -> Result<u16, crate::Error> {
        if self.tlv_tot < Self::HEADER_LEN {
            return Err(crate::Error::InvalidTlvLength);
        }
        Ok(self.tlv_tot - Self::HEADER_LEN)
    }
}
