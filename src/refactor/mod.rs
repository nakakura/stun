pub mod rfc3489;
pub mod rfc5389;

use byteorder::{BigEndian, WriteBytesExt};
use nom::*;
use rand::prelude::*;

#[cfg(test)]
use hex;

use super::error;

#[derive(Clone, Debug, PartialEq)]
pub enum AttributeEnum {
}

#[derive(Debug)]
pub struct StunMessage {
    pub header: StunHeader,
    pub attributes: Vec<AttributeEnum>,
}

impl StunMessage {
    pub fn new(header: StunHeader, attributes: Vec<AttributeEnum>) -> Self {
        StunMessage {
            header: header,
            attributes: attributes
        }
    }

    //FIXME
    //Stun Headerのvalidation,
    //AttributeのParse Errorを省いている
    pub fn decode(data: &[u8]) -> Result<Self, error::ErrorEnum> {
        let (buf, header) = StunHeader::decode(data)?;
        let item = RawAttributesIter { buf: buf };
        Ok(Self::new(header, item.filter_map(|x| match x {
            Ok(x) => Some(x),
            Err(_) => None,
        }).filter_map(|x| match x.build() {
            Ok(x) => {
                Some(x)
            },
            Err(_) => None
        }).collect()))
    }
}

#[derive(Debug)]
pub struct StunHeader {
    message_type: u16,
    length: u16,
    transaction_id: [u8; 16],
}

impl StunHeader {
    pub fn new(message_type: u16, length: u16, transaction_id: [u8;16]) -> Self {
        StunHeader {
            message_type: message_type,
            length: length,
            transaction_id: transaction_id
        }
    }

    pub fn decode(i: &[u8]) -> IResult<&[u8], StunHeader> {
        do_parse!(i,
           p_type: be_u16
        >> len: be_u16
        >> transaction_id: take!(16)
        >> (
            {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&transaction_id[0..16]);
                StunHeader::new(p_type, len, arr)
            }
           )
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, error::ErrorEnum> {
        let mut wtr = vec![];
        wtr.write_u16::<BigEndian>(self.message_type)?;
        wtr.write_u16::<BigEndian>(self.length)?;
        wtr.extend_from_slice(&self.transaction_id);
        Ok(wtr)
    }
}

#[test]
fn test_stun_header() {
    let buf: &[u8] = &[0, 1, 0, 76, 33, 18, 164, 66, 82, 71, 67, 56, 88, 105, 54, 98, 113, 88, 103, 101, 0, 6, 0, 9, 56, 109, 85, 101, 58, 101, 84, 121, 85, 0, 0, 0, 192, 87, 0, 4, 0, 1, 0, 50, 128, 41, 0, 8, 181, 146, 46, 193, 138, 167, 124, 187, 0, 36, 0, 4, 110, 127, 30, 255, 0, 8, 0, 20, 186, 249, 61, 252, 62, 80, 134, 224, 82, 182, 196, 9, 154, 127, 17, 230, 174, 236, 6, 245, 128, 40, 0, 4, 100, 23, 16, 236];
    let header = StunHeader::decode(buf);
    assert!(header.is_ok());
}

#[test]
fn test_stun_header_err_too_short() {
    let buf: &[u8] = &[0, 1];
    let header = StunHeader::decode(buf);
    assert!(header.is_err());
}

struct RawAttribute<'a> {
    a_type: u16,
    len: u16,
    payload: &'a[u8],
}

impl<'a> RawAttribute<'a> {
    //FIXME
    pub fn build(&'a self) -> Result<AttributeEnum, error::ErrorEnum> {
        match self.a_type {

            _ => {}
        }
        unreachable!()
    }
}

struct RawAttributesIter<'a> {
    buf: &'a[u8]
}

impl<'a> RawAttributesIter<'a> {
    fn extract(i: &'a[u8]) -> IResult<&[u8], RawAttribute> {
        do_parse!(i,
               a_type: be_u16
            >> len: be_u16
            >> payload: take!(len)
            >> padding: take!((4 - len % 4) % 4) //attributeの切れ目は4の倍数までのため、余分なpaddingは捨てる
            >> (RawAttribute {
                    a_type: a_type,
                    len: len,
                    payload: payload
               })
        )
    }
}

impl<'a> Iterator for RawAttributesIter<'a> {
    type Item = Result<RawAttribute<'a>, error::ErrorEnum>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() == 0 {
            return None
        }

        let data = RawAttributesIter::extract(&self.buf);
        match data {
            Err(e) => Some(Err(e.into())),
            Ok((i, attribute)) => {
                self.buf = i;
                Some(Ok(attribute))
            }
        }
    }
}

// Binding Response
// MAPPED-ADDRESS
// SOURCE-ADDRESS
// CHANGED-ADDRESS
// SOFTWARE(not in 3489)
#[test]
fn test_raw_attribute_iteration() {
    let buf: &[u8] = &[0, 1, 0, 8, 0, 1, 114, 231, 115, 69, 230, 148, 0, 4, 0, 8, 0, 1, 1, 187, 52, 194, 239, 198, 0, 5, 0, 8, 0, 1, 1, 187, 52, 194, 239, 198, 128, 34, 0, 32, 67, 105, 116, 114, 105, 120, 45, 51, 46, 50, 46, 53, 46, 57, 32, 39, 77, 97, 114, 115, 104, 97, 108, 32, 87, 101, 115, 116, 39, 0, 0, 0];
    let item = RawAttributesIter { buf: buf };
    let items: Vec<Result<RawAttribute, error::ErrorEnum>> = item.collect();
    assert_eq!(items.len(), 4);
}

//0001004c2112a44252474338586936627158676500060009386d55653a65547955000000c05700040001003280290008b5922ec18aa77cbb002400046e7f1eff00080014baf93dfc3e5086e052b6c4099a7f11e6aeec06f580280004641710ec
//USERNAME
//Unknown
//ICE-CONTROLLED
//PRIORITY
//MESSAGE-INTEGRITY
//FINGERPRINT
#[test]
fn test_raw_attribute_iteration_with_padding() {
    let buf: &[u8] = &[0, 6, 0, 9, 56, 109, 85, 101, 58, 101, 84, 121, 85, 0, 0, 0, 192, 87, 0, 4, 0, 1, 0, 50, 128, 41, 0, 8, 181, 146, 46, 193, 138, 167, 124, 187, 0, 36, 0, 4, 110, 127, 30, 255, 0, 8, 0, 20, 186, 249, 61, 252, 62, 80, 134, 224, 82, 182, 196, 9, 154, 127, 17, 230, 174, 236, 6, 245, 128, 40, 0, 4, 100, 23, 16, 236];
    let item = RawAttributesIter { buf: buf };
    let items: Vec<Result<RawAttribute, error::ErrorEnum>> = item.collect();
    assert_eq!(items.len(), 6);
}

#[test]
fn test_raw_attribute_iteration_broken_message() {
    let buf: &[u8] = &[0, 6, 0, 9, 56, 109, 85, 101, 58, 84, 121, 85, 0, 0, 0, 192, 87, 0, 4, 0, 1, 0, 50, 128, 41, 0, 8, 181, 146, 46, 193, 138, 167, 124, 187, 0, 36, 0, 4, 110, 127, 30, 255, 0, 8, 0, 20, 186, 249, 61, 252, 62, 80, 134, 224, 82, 182, 196, 9, 154, 127, 17, 230, 174, 236, 6, 245, 128, 40, 0, 4, 100, 23, 16, 236];
    let mut item_iter = RawAttributesIter { buf: buf };
    let item = item_iter.next();
    assert!(item.is_some());
    assert!(item.unwrap().is_ok());
    let item = item_iter.next();
    assert!(item.is_some());
    assert!(item.unwrap().is_err());
}