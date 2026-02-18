/// This is a library for parsing and verifying mcuboot images as per the documentation at https://docs.mcuboot.com/design.html#image-format
///
mod error;
mod image_header;
mod image_tlv;
mod mcuboot_constants;

use std::{fs::File, io::Cursor, path::Path};

use log::trace;

use crate::{
    error::Error,
    image_header::ImageHeader,
    image_tlv::{
        ImageTlvAreaHeader, ImageTlvAreaType, ImageTlvEntry, ImageTlvEntryType, TakeTlvEntry,
    },
};

#[derive(Debug)]
/// Struct containing all the relevant metadata of a mcuboot image
pub struct ImageMetadata {
    pub header: ImageHeader,
    // pub protected_tlvs: Option<Vec<ImageTlvEntry>>, currently not implemented
    pub sha256_hash: Vec<u8>,
    pub signature_key_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Parses the provided mcuboot image and returns the corresponding `ImageMetadata`.
/// Usage:
/// 
/// ```
/// let path = std::path::Path::new("test/test_image.signed.bin");
/// let image_metadata = mcuboot_rs::parse_image(&path).expect("Failed to parse image");
/// println!("Image header:\n{:#?}", image_metadata.header);
/// println!("Image sha256_hash: {:#?}", image_metadata.sha256_hash);
/// println!("Image signature: {:#?}", image_metadata.signature);
/// println!("Image signature_key_hash: {:#?}", image_metadata.signature_key_hash);
/// ``` 
/// 
pub fn parse_image(path: impl AsRef<Path>) -> Result<ImageMetadata, Error> {
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let mut cursor = Cursor::new(data.as_slice());

    let header: ImageHeader = (&mut cursor).try_into()?;
    trace!("Image header: {:#?}", header);

    // Move to the end of the image, pointing to the TLV area,
    cursor.set_position(header.header_size as u64 + header.image_size as u64);

    let tlv_header = ImageTlvAreaHeader::try_from(&mut cursor)?;

    let tlv_header = match tlv_header.area_type() {
        ImageTlvAreaType::Protected => {
            trace!(
                "Found TLV protected area of size: {}bytes",
                tlv_header.area_size()
            );

            // For now we simply skip the TLV area, since we are not interested in its content.
            cursor.set_position(cursor.position() + tlv_header.area_payload_size()? as u64);
            ImageTlvAreaHeader::try_from(&mut cursor)?
        }
        ImageTlvAreaType::Unprotected => tlv_header,
        ImageTlvAreaType::Invalid(magic) => return Err(Error::InvalidTlvMagic(magic)),
    };

    // Here we expect a non-protected TLV area
    let area_type = tlv_header.area_type();
    if let ImageTlvAreaType::Invalid(_) | ImageTlvAreaType::Protected = area_type {
        return Err(Error::NonProtectedTlvAreaNotFound(area_type));
    }

    trace!(
        "Reading TLV entries from TLV area ({}bytes)",
        tlv_header.area_size()
    );

    let mut unprotected_tlvs = read_tlv_entries(&mut cursor, &tlv_header)?;

    // In this area, the order of the TLV is guaranteed to be:
    // 1) SHA256
    // 2) KeyHash
    // 3) Signature
    // See https://docs.mcuboot.com/design.html#image-format
    let signature = unprotected_tlvs.take(ImageTlvEntryType::EcdsaSig)?.value;
    let signature_key_hash = unprotected_tlvs.take(ImageTlvEntryType::KeyHash)?.value;
    let sha256_hash = unprotected_tlvs.take(ImageTlvEntryType::Sha256)?.value;

    Ok(ImageMetadata {
        header,
        sha256_hash,
        signature_key_hash,
        signature,
    })
}

fn read_tlv_entries(
    cursor: &mut Cursor<&[u8]>,
    tlv_header: &ImageTlvAreaHeader,
) -> Result<Vec<ImageTlvEntry>, Error> {
    let mut tlvs = Vec::new();

    let end_of_area = cursor.position() + tlv_header.area_payload_size()? as u64;
    while cursor.position() < end_of_area {
        let tlv_entry = ImageTlvEntry::try_from(&mut *cursor)?;
        trace!(
            "Read TLV entry: {}, {:?}, value: {:x?}",
            tlv_entry.len, tlv_entry.type_, tlv_entry.value
        );
        tlvs.push(tlv_entry);
    }
    Ok(tlvs)
}

fn read_u8(c: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    use std::io::Read;

    let mut buf = [0u8; 1];
    c.read_exact(&mut buf).map_err(Error::ImageParsing)?;
    Ok(buf[0])
}

fn read_u16(c: &mut Cursor<&[u8]>) -> Result<u16, Error> {
    use std::io::Read;

    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).map_err(Error::ImageParsing)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(c: &mut Cursor<&[u8]>) -> Result<u32, Error> {
    use std::io::Read;

    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).map_err(Error::ImageParsing)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_valid_image_works() {
        let path = Path::new("test/test_image.signed.bin");
        let image = parse_image(&path).expect("Failed to parse valid image");

        println!("Image:\n{:#x?}", image);

        assert_eq!(image.header.protect_tlv_size, 0);
        assert_eq!(image.header.image_size, 852540);
        assert_eq!(
            image.header.flags,
            mcuboot_constants::ImageHeaderFlags::empty()
        );
        assert_eq!(image.header.version.major, 1);
        assert_eq!(image.header.version.minor, 4);
        assert_eq!(image.header.version.revision, 2);
        assert_eq!(image.header.version.build_num, 0);
        assert_eq!(
            image.sha256_hash,
            vec![
                0x80, 0xf3, 0xc5, 0xfb, 0x50, 0xa0, 0x16, 0xc1, 0xf6, 0xe4, 0x57, 0x49, 0x96, 0x47,
                0x2e, 0xb3, 0xf7, 0xb6, 0x14, 0xee, 0xc2, 0xd6, 0xa5, 0xd0, 0x96, 0xbc, 0x7, 0xb6,
                0x9a, 0x2d, 0x81, 0x21
            ]
        );
        assert_eq!(
            image.signature_key_hash,
            vec![
                0xe3, 0x4, 0x66, 0xf6, 0xb8, 0x47, 0xc, 0x1f, 0x29, 0x7, 0xb, 0x17, 0xf1, 0xe2,
                0xd3, 0xe9, 0x4d, 0x44, 0x5e, 0x3f, 0x60, 0x80, 0x87, 0xfd, 0xc7, 0x11, 0xe4, 0x38,
                0x2b, 0xb5, 0x38, 0xb6
            ]
        );
        assert_eq!(
            image.signature,
            vec![
                0x30, 0x44, 0x2, 0x20, 0x23, 0x14, 0xd5, 0xd3, 0x86, 0xeb, 0x61, 0x1d, 0xd6, 0xf5,
                0xa9, 0xa8, 0x2, 0xcf, 0x7e, 0x26, 0xcc, 0x95, 0x57, 0x99, 0x43, 0xf5, 0xd6, 0xa5,
                0xd0, 0x30, 0xe6, 0x22, 0x73, 0x26, 0x56, 0x92, 0x2, 0x20, 0xa, 0x30, 0xf7, 0x54,
                0xb2, 0x1c, 0x22, 0x23, 0xe1, 0x75, 0xfa, 0x43, 0x49, 0x3b, 0xc1, 0x87, 0x41, 0x32,
                0xab, 0xa4, 0xc3, 0xc4, 0xba, 0x75, 0xd, 0xc4, 0xa4, 0x18, 0xc4, 0x9e, 0xea, 0x83
            ]
        );
    }

    #[test]
    fn parsing_valid_encrypted_image_works() {
        let path = Path::new("test/test_image.signed.encrypted.ota.bin");
        let image = parse_image(&path).expect("Failed to parse valid image");

        println!("Image Header:\n{:#x?}", image);

        assert_eq!(image.header.protect_tlv_size, 0);
        assert_eq!(image.header.image_size, 852544);
        assert_eq!(
            image.header.flags,
            mcuboot_constants::ImageHeaderFlags::IMAGE_F_ENCRYPTED_AES128
        );
        assert_eq!(image.header.version.major, 1);
        assert_eq!(image.header.version.minor, 4);
        assert_eq!(image.header.version.revision, 2);
        assert_eq!(image.header.version.build_num, 0);
        assert_eq!(
            image.sha256_hash,
            vec![
                0x3, 0xb3, 0xbb, 0x6a, 0xfb, 0x5b, 0xce, 0xb2, 0xef, 0x45, 0x20, 0x69, 0x25, 0x38,
                0xbe, 0xd7, 0xed, 0x1b, 0xb4, 0x9a, 0xfd, 0xd1, 0xab, 0x56, 0x91, 0x1d, 0x13, 0x5f,
                0x4, 0xa3, 0x41, 0x7a
            ]
        );
        assert_eq!(
            image.signature_key_hash,
            vec![
                0xe3, 0x4, 0x66, 0xf6, 0xb8, 0x47, 0xc, 0x1f, 0x29, 0x7, 0xb, 0x17, 0xf1, 0xe2,
                0xd3, 0xe9, 0x4d, 0x44, 0x5e, 0x3f, 0x60, 0x80, 0x87, 0xfd, 0xc7, 0x11, 0xe4, 0x38,
                0x2b, 0xb5, 0x38, 0xb6
            ]
        );
        assert_eq!(
            image.signature,
            vec![
                0x30, 0x45, 0x2, 0x21, 0x0, 0xc2, 0x68, 0xa8, 0x4a, 0x21, 0x3b, 0xc1, 0x97, 0xc7,
                0x5c, 0x4e, 0x3c, 0xf0, 0x8f, 0x58, 0xe2, 0x79, 0xf1, 0xb1, 0xb4, 0x94, 0x5a, 0x9e,
                0x8f, 0xb0, 0x1b, 0x21, 0x58, 0x95, 0xaa, 0xe5, 0xdb, 0x2, 0x20, 0x17, 0x83, 0xb8,
                0x10, 0x7c, 0xb4, 0x49, 0x25, 0xbb, 0x2f, 0x44, 0x2d, 0x6c, 0x7b, 0x29, 0x8f, 0x15,
                0x3d, 0x6a, 0x7, 0x33, 0xfe, 0x9b, 0x3e, 0xb7, 0x91, 0xe8, 0xa0, 0x19, 0x98, 0x81,
                0x16
            ]
        );
    }
}
