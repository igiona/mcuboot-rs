use crate::image_tlv::ImageTlvAreaType;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("unable to parse image: {0}")]
    ImageParsing(std::io::Error),
    #[error("invalid image header magic: 0x{0:08x}")]
    InvalidHeaderMagic(u32),
    #[error("image TLV entry type: 0x{0:04x} not found")]
    TlvEntryTypeNotFound(u16),
    #[error("invalid image TLV magic: 0x{0:04x}")]
    InvalidTlvMagic(u16),
    #[error("missing non-protected TLV area. Found instead: {0:?}")]
    NonProtectedTlvAreaNotFound(ImageTlvAreaType),
    #[error("invalid image TLV length")]
    InvalidTlvLength,
}
