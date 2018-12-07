pub mod attributes;

use byteorder::{BigEndian, WriteBytesExt};
use nom::*;
use rand::prelude::*;

#[cfg(test)]
use hex;

use super::error;

#[derive(Debug)]
pub struct StunMessage {
    pub header: StunHeader,
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    pub fn new(header: StunHeader, attributes: Vec<Attribute>) -> Self {
        StunMessage {
            header: header,
            attributes: attributes
        }
    }

    pub fn create_from_attributes(a_type: u16, attributes: Vec<Attribute>) -> Self {
        let len = attributes.iter().fold(0, |sum, x| {
            sum + x.encode().unwrap().len()
        });

        let header = StunHeader::create_from_type_and_len(a_type, len as u16);
        Self::new(header, attributes)
    }

    pub fn decode(data: &[u8]) -> Result<Self, error::ErrorEnum> {
        let (buf, header) = StunHeader::decode(data)?;
        let item = RawAttributesIter { buf: buf.to_vec() };
        Ok(Self::new(header, item.filter_map(|x| match x.build() {
            Ok(x) => Some(x),
            Err(_) => None
        }).collect()))
    }

    pub fn encode(&self) -> Result<Vec<u8>, error::ErrorEnum> {
        let mut vec = self.header.encode()?;
        for x in self.attributes.iter() {
            x.encode().map(|v| {
                vec.extend_from_slice(&v);
            });
        }
        Ok(vec)
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

    pub fn create_from_type_and_len(m_type: u16, length: u16) -> Self {
        let mut rng = rand::thread_rng();
        let transaction_1: u64 = rng.gen();
        let transaction_2: u64 = rng.gen();
        let transaction_id = unsafe { ::std::mem::transmute::<[u64;2], [u8;16]>( [transaction_1, transaction_2] ) };
        Self::new(m_type, length, transaction_id)
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

#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub enum Attribute {
    MappedAddress(attributes::MappedAddress),
    ResponseAddress(attributes::ResponseAddress),
    ChangeRequest(attributes::ChangeRequest),
    SourceAddress(attributes::SourceAddress),
    ChangedAddress(attributes::ChangedAddress),
    UserName(attributes::UserName),
    Password(attributes::Password),
    MessageIntegrity(attributes::MessageIntegrity),
    ErrorCode(attributes::ErrorCode),
    UnknownAttributes(attributes::Unknown),
    ReflectedFrom(attributes::ReflectedFrom),
}

impl Attribute {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let enc_opt = match self {
            Attribute::MappedAddress(ref i) => Some((1, i.encode())),
            Attribute::ResponseAddress(ref i) => Some((2, i.encode())),
            Attribute::ChangeRequest(ref i) => Some((3, i.encode())),
            Attribute::SourceAddress(ref i) => Some((4, i.encode())),
            Attribute::ChangedAddress(ref i) => Some((5, i.encode())),
            Attribute::UserName(ref i) => Some((6, i.encode())),
            Attribute::Password(ref i) => Some((7, i.encode())),
            Attribute::MessageIntegrity(ref i) => Some((8, i.encode())),
            Attribute::ErrorCode(ref i) => Some((9, i.encode())),
            Attribute::UnknownAttributes(ref i) => Some((10, i.encode())),
            Attribute::ReflectedFrom(ref i) => Some((11, i.encode())),
        };

        match enc_opt {
            Some((_, Err(_e))) => None,
            Some((a_type, Ok(buf))) => {
                let x: Result<Vec<u8>, error::ErrorEnum> = (|| {
                    let mut wtr = vec![];
                    wtr.write_u16::<BigEndian>(a_type)?;
                    wtr.write_u16::<BigEndian>(buf.len() as u16)?;
                    wtr.extend_from_slice(&buf);
                    Ok(wtr)
                })();
                if let Ok(vec) = x {
                    Some(vec)
                } else {
                    None
                }
           },
            _ => None
        }
    }
}

#[derive(Clone, Debug, PartialOrd, PartialEq)]
struct RawAttribute {
    a_type: u16,
    length: u16,
    value: Vec<u8>,
}

impl RawAttribute {
    pub fn build(&self) -> Result<Attribute, error::ErrorEnum> {
        match self.a_type {
            1 => {
                Ok(Attribute::MappedAddress(attributes::MappedAddress::decode(&self.value)?))
            },
            2 => {
                Ok(Attribute::ResponseAddress(attributes::ResponseAddress::decode(&self.value)?))
            },
            3 => {
                Ok(Attribute::ChangeRequest(attributes::ChangeRequest::decode(&self.value)?))
            },
            4 => {
                Ok(Attribute::SourceAddress(attributes::SourceAddress::decode(&self.value)?))
            },
            5 => {
                Ok(Attribute::ChangedAddress(attributes::ChangedAddress::decode(&self.value)?))
            },
            6 => {
                Ok(Attribute::UserName(attributes::UserName::decode(&self.value)?))
            },
            7 => {
                Ok(Attribute::Password(attributes::Password::decode(&self.value)?))
            },
            8 => {
                Ok(Attribute::MessageIntegrity(attributes::MessageIntegrity::decode(&self.value)?))
            },
            9 => {
                Ok(Attribute::ErrorCode(attributes::ErrorCode::decode(&self.value)?))
            },
            10 => {
                Ok(Attribute::UnknownAttributes(attributes::Unknown::decode(&self.value)?))
            },
            11 => {
                Ok(Attribute::ReflectedFrom(attributes::ReflectedFrom::decode(&self.value)?))
            },
            _ => {
                Err("invalid attibute type".to_string()).map_err(Into::into)
            }
        }
    }
}

struct RawAttributesIter {
    buf: Vec<u8>
}

impl Iterator for RawAttributesIter {
    type Item = RawAttribute;

    fn next(&mut self) -> Option<Self::Item> {
        let data = extract(&self.buf);
        match data {
            Err(_) => None,
            Ok((i, attribute)) => {
                self.buf = i.to_vec();
                Some(attribute)
            }
        }
    }
}

fn extract(i: &[u8]) -> IResult<&[u8], RawAttribute> {
    do_parse!(i,
               a_type: be_u16
            >> len: be_u16
            >> payload: take!(len)
            >> (
                RawAttribute {
                    a_type: a_type,
                    length: len,
                    value: payload.to_vec()
                }
            )
        )
}

// Binding Response
// MAPPED-ADDRESS
// SOURCE-ADDRESS
// CHANGED-ADDRESS
// SOFTWARE(not in 3489)
// "0101004801ace636e501b3134502510e5c5c220e00010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"
#[test]
fn test_decode_binding_response() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0101004801ace636e501b3134502510e5c5c220e00010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000").unwrap();
    let x = StunMessage::decode(&vec).unwrap();

    let binary = x.encode().unwrap();
    //because RFC 3489 doesn't include SOFTWARE attribute
    assert_eq!(vec[0..56].to_vec(), binary);
    assert_ne!(vec, binary);
}

// Binding Request
// CHANGE-REQUEST
// ""
#[test]
fn test_decode_binding_request() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0001000802aa4e5efc98eb1acd28b659399b85480003000400000004").unwrap();
    let x = StunMessage::decode(&vec).unwrap();

    let binary = x.encode().unwrap();
    assert_eq!(vec, binary);
}

// Binding Response
// MAPPED-ADDRESS
// SOURCE-ADDRESS
// CHANGED-ADDRESS
// SOFTWARE(not in 3489)
// "0101004801ace636e501b3134502510e5c5c220e00010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"
#[test]
fn test_decode_binding_response2() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0101004801ace636e501b3134502510e5c5c220e00010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000").unwrap();
    let x = StunMessage::decode(&vec).unwrap();

    let binary = x.encode().unwrap();
    //because RFC 3489 doesn't include SOFTWARE attribute
    assert_eq!(vec[0..56].to_vec(), binary);
    assert_ne!(vec, binary);
}

// Binding Error Response
// ERROR-CODE
// SOFTWARE
// "0111007402aa4e5efc98eb1acd28b659399b85480009004c00000414556e6b6e6f776e206174747269627574653a205455524e207365727665722077617320636f6e6669677572656420776974686f757420524643203537383020737570706f72740000802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"
#[test]
fn test_decode_binding_error_response() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0111007402aa4e5efc98eb1acd28b659399b85480009004c00000414556e6b6e6f776e206174747269627574653a205455524e207365727665722077617320636f6e6669677572656420776974686f757420524643203537383020737570706f72740000802200204369747269782d332e322e352e3920274d61727368616c205765737427000000").unwrap();
    let x = StunMessage::decode(&vec).unwrap();
    let binary = x.encode().unwrap();
    //because RFC 3489 doesn't include SOFTWARE attribute
    assert_eq!(vec[0..100].to_vec(), binary);
    assert_ne!(vec, binary);
}

// Binding Request
// CHANGE-REQUEST
// "0001000803e5315f6932a542f14e0d2d83e97c1e0003000400000002"
#[test]
fn test_decode_binding_request2() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0001000803e5315f6932a542f14e0d2d83e97c1e0003000400000002").unwrap();
    let x = StunMessage::decode(&vec).unwrap();
    let binary = x.encode();
    assert_eq!(vec, binary.unwrap());
}

// Binding Error Response
// ERROR-CODE
// SERVER
// "0111007403e5315f6932a542f14e0d2d83e97c1e0009004c00000414556e6b6e6f776e206174747269627574653a205455524e207365727665722077617320636f6e6669677572656420776974686f757420524643203537383020737570706f72740000802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"

// Binding Request
// CHANGE-REQUEST
// "000100080a32a76f4c99291fb146c42cefe992370003000400000000"

// Binding Response
// MAPPED-ADDRESS
// SOURCE-ADDRESS
// CHANGED-ADDRESS
// SERVER
// "010100480a32a76f4c99291fb146c42cefe9923700010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"

// Binding Request
// CHANGE-REQUEST
// "000100080bbd835b21afb91a725d630ade5e10100003000400000000"

// Binding Request
// CHANGE-REQUEST
// "000100080b2f5a130ddeac4fef569a5aa293813c0003000400000000"

// Binding Request
// CHANGE-REQUEST
// "000100080b4ead7b9703b37a2bd0b33a200bdc2f0003000400000000"

// Binding Request
