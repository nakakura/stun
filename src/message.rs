use std::mem;
use std::net::Ipv4Addr;

use nom::*;

#[cfg(test)]
use hex;

#[derive(Debug)]
pub struct StunMessage {
    pub header: StunHeader,
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    pub fn new(data: &[u8]) -> Option<Self> {
        if let Ok((buf, data)) = parse_header(data) {
            let body = data.1;
            let mut item = RawAttributesIter { buf: body };
            Some(StunMessage {
                header: data.0?,
                attributes: item.filter_map(|x| x.build() ).collect()
            })
        } else {
            None
        }
   }
}

#[derive(Debug)]
pub struct StunHeader {
    message_type: u16,
    length: u16,
    transaction_id: [u8; 16],
}

impl StunHeader {
    pub fn new(message_type: u16, length: u16, transaction_id: &[u8]) -> Option<Self> {
        if transaction_id.len() != 16 {
            None
        } else {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&transaction_id[0..16]);
            Some(StunHeader {
                message_type: message_type,
                length: length,
                transaction_id: arr
            })
        }
    }
}
#[derive(Debug)]
pub enum Attribute {
    MappedAddress(MappedAddress),
    ResponseAddress(ResponseAddress),
    ChangeRequest(ChangeRequest),
    SourceAddress(SourceAddress),
    ChangedAddress(ChangedAddress),
    UserName(UserName),
    Password(Password),
    MessageIntegrity(MessageIntegrity),
    ErrorCode(ErrorCode),
    UnknownAttributes(Unknown),
    ReflectedFrom(ReflectedFrom),
}

// 11.2.1 MAPPED-ADDRESS
//
//   The MAPPED-ADDRESS attribute indicates the mapped IP address and
//   port.  It consists of an eight bit address family, and a sixteen bit
//   port, followed by a fixed length value representing the IP address.
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |x x x x x x x x|    Family     |           Port                |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             Address                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The port is a network byte ordered representation of the mapped port.
//   The address family is always 0x01, corresponding to IPv4.  The first
//   8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
//   aligning parameters on natural boundaries.  The IPv4 address is 32
//   bits.
#[derive(Debug)]
pub struct MappedAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl MappedAddress {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = MappedAddress::parse(i) {
            Some(MappedAddress {
                family: family,
                port: port,
                address: Ipv4Addr::new(address[0], address[1], address[2], address[3])
            })
        } else {
            None
        }
   }

    fn parse(i: &[u8]) -> IResult<&[u8], (u8, u16, [u8;4])> {
         do_parse!(i,
            x: be_u8
            >> a_type: be_u8
            >> port: be_u16
            >> address: be_u32
            >> (a_type, port, unsafe { mem::transmute::<u32, [u8;4]>(address) })
        )
    }
}

// 11.2.2 RESPONSE-ADDRESS
//
//   The RESPONSE-ADDRESS attribute indicates where the response to a
//   Binding Request should be sent.  Its syntax is identical to MAPPED-
//   ADDRESS.
#[derive(Debug)]
pub struct ResponseAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl ResponseAddress {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = MappedAddress::parse(i) {
            Some(ResponseAddress {
                family: family,
                port: port,
                address: Ipv4Addr::new(address[0], address[1], address[2], address[3])
            })
        } else {
            None
        }
    }
}

// 11.2.3  CHANGED-ADDRESS
//
//   The CHANGED-ADDRESS attribute indicates the IP address and port where
//   responses would have been sent from if the "change IP" and "change
//   port" flags had been set in the CHANGE-REQUEST attribute of the
//   Binding Request.  The attribute is always present in a Binding
//   Response, independent of the value of the flags.  Its syntax is
//   identical to MAPPED-ADDRESS.
#[derive(Debug)]
pub struct ChangedAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl ChangedAddress {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = MappedAddress::parse(i) {
            Some(ChangedAddress {
                family: family,
                port: port,
                address: Ipv4Addr::new(address[0], address[1], address[2], address[3])
            })
        } else {
            None
        }
    }
}

// 11.2.4 CHANGE-REQUEST
//
//   The CHANGE-REQUEST attribute is used by the client to request that
//   the server use a different address and/or port when sending the
//   response.  The attribute is 32 bits long, although only two bits (A
//   and B) are used:
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The meaning of the flags is:
//
//   A: This is the "change IP" flag.  If true, it requests the server
//      to send the Binding Response with a different IP address than the
//      one the Binding Request was received on.
//
//   B: This is the "change port" flag.  If true, it requests the
//      server to send the Binding Response with a different port than the
//      one the Binding Request was received on.
#[derive(Debug)]
pub struct ChangeRequest {
    a: bool,
    b: bool,
}

impl ChangeRequest {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (a, b))) = ChangeRequest::parse(i) {
            Some(ChangeRequest {
                a: a,
                b: b,
            })
        } else {
            None
        }
    }

    fn parse(i: &[u8]) -> IResult<&[u8], (bool, bool)> {
        do_parse!(i,
            _x: take!(3)
            >> last_byte: bits!(tuple!(take_bits!(u8, 1), take_bits!(u8, 1), take_bits!(u8, 1), take_bits!(u8, 1)))
            >> (last_byte.1 == 1, last_byte.1 == 1)
        )
    }
}

// 11.2.5 SOURCE-ADDRESS
//
//   The SOURCE-ADDRESS attribute is present in Binding Responses.  It
//   indicates the source IP address and port that the server is sending
//   the response from.  Its syntax is identical to that of MAPPED-
//   ADDRESS.
#[derive(Debug)]
pub struct SourceAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl SourceAddress {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = MappedAddress::parse(i) {
            Some(SourceAddress {
                family: family,
                port: port,
                address: Ipv4Addr::new(address[0], address[1], address[2], address[3])
            })
        } else {
            None
        }
    }
}

// 11.2.6 USERNAME
//
//   The USERNAME attribute is used for message integrity.  It serves as a
//   means to identify the shared secret used in the message integrity
//   check.  The USERNAME is always present in a Shared Secret Response,
//   along with the PASSWORD.  It is optionally present in a Binding
//   Request when message integrity is used.
//   The value of USERNAME is a variable length opaque value.  Its length
//   MUST be a multiple of 4 (measured in bytes) in order to guarantee
//   alignment of attributes on word boundaries.
#[derive(Debug)]
pub struct UserName {
    user_name: String
}

impl UserName {
    pub fn new(i: &[u8]) -> Option<Self> {
        match String::from_utf8(i.to_vec()) {
            Ok(x) => Some(UserName {
                user_name: x
            }),
            Err(e) => None,
        }
    }
}

// 11.2.7 PASSWORD
//
//   The PASSWORD attribute is used in Shared Secret Responses.  It is
//   always present in a Shared Secret Response, along with the USERNAME.
//
//   The value of PASSWORD is a variable length value that is to be used
//   as a shared secret.  Its length MUST be a multiple of 4 (measured in
//   bytes) in order to guarantee alignment of attributes on word
//   boundaries.
#[derive(Debug)]
pub struct Password {
    password: String
}

impl Password {
    pub fn new(i: &[u8]) -> Option<Self> {
        match String::from_utf8(i.to_vec()) {
            Ok(x) => Some(Password {
                password: x
            }),
            Err(e) => None,
        }
    }
}

// 11.2.8 MESSAGE-INTEGRITY
//
//   The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [13] of the
//   STUN message.  It can be present in Binding Requests or Binding
//   Responses.  Since it uses the SHA1 hash, the HMAC will be 20 bytes.
//   The text used as input to HMAC is the STUN message, including the
//   header, up to and including the attribute preceding the MESSAGE-
//   INTEGRITY attribute. That text is then padded with zeroes so as to be
//   a multiple of 64 bytes.  As a result, the MESSAGE-INTEGRITY attribute
//   MUST be the last attribute in any STUN message.  The key used as
//   input to HMAC depends on the context.
#[derive(Debug)]
pub struct MessageIntegrity {
    hmac: String
}

impl MessageIntegrity {
    pub fn new(i: &[u8]) -> Option<Self> {
        match String::from_utf8(i.to_vec()) {
            Ok(x) => Some(MessageIntegrity {
                hmac: x
            }),
            Err(e) => None,
        }
    }
}

// 11.2.9 ERROR-CODE
//
//   The ERROR-CODE attribute is present in the Binding Error Response and
//   Shared Secret Error Response.  It is a numeric value in the range of
//   100 to 699 plus a textual reason phrase encoded in UTF-8, and is
//   consistent in its code assignments and semantics with SIP [10] and
//   HTTP [15].  The reason phrase is meant for user consumption, and can
//   be anything appropriate for the response code.  The lengths of the
//   reason phrases MUST be a multiple of 4 (measured in bytes).  This can
//   be accomplished by added spaces to the end of the text, if necessary.
//   Recommended reason phrases for the defined response codes are
//   presented below.
//
//   To facilitate processing, the class of the error code (the hundreds
//   digit) is encoded separately from the rest of the code.
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                   0                     |Class|     Number    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |      Reason Phrase (variable)                                ..
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   The class represents the hundreds digit of the response code.  The
//   value MUST be between 1 and 6.  The number represents the response
//   code modulo 100, and its value MUST be between 0 and 99.
//
//   The following response codes, along with their recommended reason
//   phrases (in brackets) are defined at this time:
//
//   400 (Bad Request): The request was malformed.  The client should not
//        retry the request without modification from the previous
//        attempt.
//
//   401 (Unauthorized): The Binding Request did not contain a MESSAGE-
//        INTEGRITY attribute.
//
//   420 (Unknown Attribute): The server did not understand a mandatory
//        attribute in the request.
//
//   430 (Stale Credentials): The Binding Request did contain a MESSAGE-
//        INTEGRITY attribute, but it used a shared secret that has
//        expired.  The client should obtain a new shared secret and try
//        again.
//
//   431 (Integrity Check Failure): The Binding Request contained a
//        MESSAGE-INTEGRITY attribute, but the HMAC failed verification.
//        This could be a sign of a potential attack, or client
//        implementation error.
//
//   432 (Missing Username): The Binding Request contained a MESSAGE-
//        INTEGRITY attribute, but not a USERNAME attribute.  Both must be
//        present for integrity checks.
//
//   433 (Use TLS): The Shared Secret request has to be sent over TLS, but
//        was not received over TLS.
//
//   500 (Server Error): The server has suffered a temporary error. The
//        client should try again.
//
//   600 (Global Failure:) The server is refusing to fulfill the request.
//        The client should not retry.
#[derive(Debug)]
pub struct ErrorCode {
    class: u8,
    number: u8,
    reason: String,
}

impl ErrorCode {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (class, number, reason))) = ErrorCode::parse(i) {
            match String::from_utf8(reason.to_vec()) {
                Ok(x) => Some(ErrorCode {
                    class: class,
                    number: number,
                    reason: x,
                }),
                Err(e) => None,
            }
        } else {
            None
        }
    }

    fn parse(i: &[u8]) -> IResult<&[u8], (u8, u8, &[u8])> {
        let len = i.len() - 4;
        do_parse!(i,
            _x: take!(2)
            >> class: bits!(tuple!(take_bits!(u8, 4), take_bits!(u8, 4)))
            >> number: be_u8
            >> reason: take!(len)
            >> (class.1, number, reason)
        )
    }
}

// 11.2.10 UNKNOWN-ATTRIBUTES
//
//   The UNKNOWN-ATTRIBUTES attribute is present only in a Binding Error
//   Response or Shared Secret Error Response when the response code in
//   the ERROR-CODE attribute is 420.
//
//   The attribute contains a list of 16 bit values, each of which
//   represents an attribute type that was not understood by the server.
//   If the number of unknown attributes is an odd number, one of the
//   attributes MUST be repeated in the list, so that the total length of
//   the list is a multiple of 4 bytes.
//
//   0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |      Attribute 1 Type           |     Attribute 2 Type        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |      Attribute 3 Type           |     Attribute 4 Type    ...
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct Unknown {
    attributes: Vec<u16>
}

impl Unknown {
    pub fn new(i: &[u8]) -> Self {
        let iter = UnknownIter { buf: i.to_vec() };
        let vec: Vec<u16> = iter.collect();
        Unknown {
            attributes: vec
        }
    }
}

struct UnknownIter {
    buf: Vec<u8>
}

impl UnknownIter {
    fn parse(i: &[u8]) -> IResult<&[u8], (u16)> {
        do_parse!(i,
            x: be_u16
            >> (x)
        )
    }
}

impl Iterator for UnknownIter {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        let data = UnknownIter::parse(&self.buf);
        match data {
            Err(_) => None,
            Ok((i, attribute)) => {
                self.buf = i.to_vec();
                Some(attribute)
            }
        }
    }
}

// 11.2.11 REFLECTED-FROM
//
//   The REFLECTED-FROM attribute is present only in Binding Responses,
//   when the Binding Request contained a RESPONSE-ADDRESS attribute.  The
//   attribute contains the identity (in terms of IP address) of the
//   source where the request came from.  Its purpose is to provide
//   traceability, so that a STUN server cannot be used as a reflector for
//   denial-of-service attacks.
//
//   Its syntax is identical to the MAPPED-ADDRESS attribute.
#[derive(Debug)]
pub struct ReflectedFrom {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl ReflectedFrom {
    pub fn new(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = MappedAddress::parse(i) {
            Some(ReflectedFrom {
                family: family,
                port: port,
                address: Ipv4Addr::new(address[0], address[1], address[2], address[3])
            })
        } else {
            None
        }
    }
}

fn parse_header(i: &[u8]) -> IResult<&[u8], (Option<StunHeader>, Vec<u8>)> {
    do_parse!(i,
           p_type: be_u16
        >> len: be_u16
        >> transaction_id: take!(16)
        >> payload: take!(len)
        >> (
            StunHeader::new(p_type, len, transaction_id), payload.to_vec()
           )
    )
}

#[derive(Debug)]
struct RawAttribute {
    a_type: u16,
    length: u16,
    value: Vec<u8>,
}

struct RawAttributesIter {
    buf: Vec<u8>
}

impl RawAttribute {
    pub fn build(&self) -> Option<Attribute> {
        match self.a_type {
            1 => {
                Some(Attribute::MappedAddress(MappedAddress::new(&self.value)?))
            },
            2 => {
                Some(Attribute::ResponseAddress(ResponseAddress::new(&self.value)?))
            },
            3 => {
                Some(Attribute::ChangeRequest(ChangeRequest::new(&self.value)?))
            },
            4 => {
                Some(Attribute::SourceAddress(SourceAddress::new(&self.value)?))
            },
            5 => {
                Some(Attribute::ChangedAddress(ChangedAddress::new(&self.value)?))
            },
            6 => {
                Some(Attribute::UserName(UserName::new(&self.value)?))
            },
            7 => {
                Some(Attribute::Password(Password::new(&self.value)?))
            },
            8 => {
                Some(Attribute::MessageIntegrity(MessageIntegrity::new(&self.value)?))
            },
            9 => {
                Some(Attribute::ErrorCode(ErrorCode::new(&self.value)?))
            },
            10 => {
                Some(Attribute::UnknownAttributes(Unknown::new(&self.value)))
            },
            11 => {
                Some(Attribute::ReflectedFrom(ReflectedFrom::new(&self.value)?))
            },
            _ => {
                None
            }
         }
    }
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

/*
fn sub_parse(p_type: u16, len: u16, t_id: &[u8], payload: Vec<u8>) -> StunMessage {
    println!("sub parse {} {} {:?} {:?}", p_type, len, t_id, payload);
    let mut vec: Vec<Attribute> = vec!();
    parse_attributes(&payload, &mut vec);
    StunMessage::new(p_type, len, t_id, vec)
}

fn parse_attributes(d: &[u8], vec: &mut Vec<Attribute>) {
    let e = extract(d).unwrap();
    vec.push(e.1);

    if e.0.len() > 0 {
        parse_attributes(e.0, vec)
    }
}
*/

#[test]
fn test_decode_binding_request() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0001000801ace636e501b3134502510e5c5c220e0003000400000000").unwrap();
    let x = StunMessage::new(&vec);
    println!("{:?}", x);
}

// Binding Response
// MAPPED-ADDRESS
// SOURCE-ADDRESS
// CHANGED-ADDRESS
// SERVER(not in 3489)
// "0101004801ace636e501b3134502510e5c5c220e00010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"
#[test]
fn test_decode_binding_response() {
    // a Binding Request includes a CHANGE-REQUEST
    let vec = hex::decode("0101004801ace636e501b3134502510e5c5c220e00010008000172e77345e69400040008000101bb34c2efc600050008000101bb34c2efc6802200204369747269782d332e322e352e3920274d61727368616c205765737427000000").unwrap();
    let x = StunMessage::new(&vec);
    println!("{:?}", x);
}

// Binding Request
// CHANGE-REQUEST
// "0001000802aa4e5efc98eb1acd28b659399b85480003000400000004"

// Binding Error Response
// ERROR-CODE
// SERVER
// "0111007402aa4e5efc98eb1acd28b659399b85480009004c00000414556e6b6e6f776e206174747269627574653a205455524e207365727665722077617320636f6e6669677572656420776974686f757420524643203537383020737570706f72740000802200204369747269782d332e322e352e3920274d61727368616c205765737427000000"

// Binding Request
// CHANGE-REQUEST
// "0001000803e5315f6932a542f14e0d2d83e97c1e0003000400000002"

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

