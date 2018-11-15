pub mod attributes;

use std::mem;
use std::net::Ipv4Addr;

use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use nom::*;

#[cfg(test)]
use hex;

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

    pub fn decode(data: &[u8]) -> Option<Self> {
        if let Ok((buf, data)) = StunHeader::decode(data) {
            let item = RawAttributesIter { buf: buf.to_vec() };
            Some(Self::new(data, item.filter_map(|x| x.build() ).collect()))
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
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

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
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
            _ => None
        };

        match enc_opt {
            Some((_, Err(_e))) => None,
            Some((a_type, Ok(buf))) => {
                let x: Result<Vec<u8>, ::std::io::Error> = (|| {
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
    pub fn build(&self) -> Option<Attribute> {
        match self.a_type {
            1 => {
                Some(Attribute::MappedAddress(attributes::MappedAddress::decode(&self.value)?))
            },
            2 => {
                Some(Attribute::ResponseAddress(attributes::ResponseAddress::decode(&self.value)?))
            },
            3 => {
                Some(Attribute::ChangeRequest(attributes::ChangeRequest::decode(&self.value)?))
            },
            4 => {
                Some(Attribute::SourceAddress(attributes::SourceAddress::decode(&self.value)?))
            },
            5 => {
                Some(Attribute::ChangedAddress(attributes::ChangedAddress::decode(&self.value)?))
            },
            6 => {
                Some(Attribute::UserName(attributes::UserName::decode(&self.value)?))
            },
            7 => {
                Some(Attribute::Password(attributes::Password::decode(&self.value)?))
            },
            8 => {
                Some(Attribute::MessageIntegrity(attributes::MessageIntegrity::decode(&self.value)?))
            },
            9 => {
                Some(Attribute::ErrorCode(attributes::ErrorCode::decode(&self.value)?))
            },
            10 => {
                Some(Attribute::UnknownAttributes(attributes::Unknown::decode(&self.value)))
            },
            11 => {
                Some(Attribute::ReflectedFrom(attributes::ReflectedFrom::decode(&self.value)?))
            },
            _ => {
                None
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
    let attributes = x.attributes.clone();

    /*
    let vec = attributes[0].encode().unwrap();
    let a0 = extract(&vec).unwrap().1;
    assert_eq!(a0.build(), Some(attributes[0].clone()));

    let vec = attributes[1].encode().unwrap();
    let a1 = extract(&vec).unwrap().1;
    assert_eq!(a1.build(), Some(attributes[1].clone()));

    let vec = attributes[2].encode().unwrap();
    let a2 = extract(&vec).unwrap().1;
    assert_eq!(a2.build(), Some(attributes[2].clone()));
    */

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
    let attributes = x.attributes.clone();


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
    let attributes = x.attributes.clone();

    /*
    let vec = attributes[0].encode().unwrap();
    let a0 = extract(&vec).unwrap().1;
    assert_eq!(a0.build(), Some(attributes[0].clone()));

    let vec = attributes[1].encode().unwrap();
    let a1 = extract(&vec).unwrap().1;
    assert_eq!(a1.build(), Some(attributes[1].clone()));

    let vec = attributes[2].encode().unwrap();
    let a2 = extract(&vec).unwrap().1;
    assert_eq!(a2.build(), Some(attributes[2].clone()));
    */

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
    let attributes = x.attributes.clone();
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
    let attributes = x.attributes.clone();
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
