use std::io::Cursor;

use crate::mcuboot_constants;

#[derive(Debug)]
pub struct ImageVersion {
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub build_num: u32,
}

#[derive(Debug)]
pub struct ImageHeader {
    pub magic: u32,
    pub load_addr: u32,
    /// Size of image header (bytes)
    pub header_size: u16,
    /// Size of protected TLV area (bytes)
    pub protect_tlv_size: u16,
    /// Does not include header
    pub image_size: u32,
    /// See https://docs.mcuboot.com/design.html#image-format IMAGE_F_[...]
    pub flags: mcuboot_constants::ImageHeaderFlags,
    pub version: ImageVersion,
    //_pad1: u32;
}

impl TryFrom<&mut Cursor<&[u8]>> for ImageHeader {
    type Error = crate::Error;

    fn try_from(cursor: &mut Cursor<&[u8]>) -> Result<Self, Self::Error> {
        parse_header(cursor)
    }
}

fn parse_header(c: &mut Cursor<&[u8]>) -> Result<ImageHeader, crate::Error> {
    let header = ImageHeader {
        magic: super::read_u32(c)?,
        load_addr: super::read_u32(c)?,
        header_size: super::read_u16(c)?,
        protect_tlv_size: super::read_u16(c)?,
        image_size: super::read_u32(c)?,
        flags: mcuboot_constants::ImageHeaderFlags::from_bits_retain(super::read_u32(c)?),
        version: ImageVersion {
            major: super::read_u8(c)?,
            minor: super::read_u8(c)?,
            revision: super::read_u16(c)?,
            build_num: super::read_u32(c)?,
        },
    };

    if header.magic != mcuboot_constants::IMAGE_MAGIC {
        return Err(crate::Error::InvalidHeaderMagic(header.magic));
    }

    Ok(header)
}
