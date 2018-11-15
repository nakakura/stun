use std::mem;
use std::net::Ipv4Addr;

use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use nom::*;

use super::Attribute;

#[cfg(test)]
use hex;

fn parse_addr(i: &[u8]) -> IResult<&[u8], (u8, u16, [u8;4])> {
    do_parse!(i,
            x: be_u8
            >> a_type: be_u8
            >> port: be_u16
            >> address: be_u32
            >> (a_type, port, unsafe { mem::transmute::<u32, [u8;4]>(address) })
        )
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct MappedAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl MappedAddress {
    pub fn new(family: u8, port: u16, address: Ipv4Addr) -> Self {
        MappedAddress {
            family: family,
            port: port,
            address: address
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = parse_addr(i) {
            Some(
                Self::new(family, port, Ipv4Addr::new(address[0], address[1], address[2], address[3]))
            )
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(self.family)?;
        wtr.write_u16::<BigEndian>(self.port)?;
        let addr = unsafe { mem::transmute::<[u8;4], u32>(self.address.octets()) };
        wtr.write_u32::<BigEndian>(addr)?;
        Ok(wtr)
    }
}

#[test]
fn test_enc_dec_mapped_address() {
    let map = MappedAddress::new(1, 5000, Ipv4Addr::new(192, 168, 1, 1));
    let binary = map.encode().unwrap();
    let map2 = MappedAddress::decode(&binary);
    assert_eq!(Some(map), map2);
}

// 11.2.2 RESPONSE-ADDRESS
//
//   The RESPONSE-ADDRESS attribute indicates where the response to a
//   Binding Request should be sent.  Its syntax is identical to MAPPED-
//   ADDRESS.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct ResponseAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl ResponseAddress {
    pub fn new(family: u8, port: u16, address: Ipv4Addr) -> Self {
        ResponseAddress {
            family: family,
            port: port,
            address: address
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = parse_addr(i) {
            Some(
                Self::new(family, port, Ipv4Addr::new(address[0], address[1], address[2], address[3]))
            )
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(self.family)?;
        wtr.write_u16::<BigEndian>(self.port)?;
        let addr = unsafe { mem::transmute::<[u8;4], u32>(self.address.octets()) };
        wtr.write_u32::<BigEndian>(addr)?;
        Ok(wtr)
    }
}

#[test]
fn test_enc_dec_response_address() {
    let map = ResponseAddress::new(1, 5000, Ipv4Addr::new(192, 168, 1, 1));
    let binary = map.encode().unwrap();
    let map2 = ResponseAddress::decode(&binary);
    assert_eq!(Some(map), map2);
}

// 11.2.3  CHANGED-ADDRESS
//
//   The CHANGED-ADDRESS attribute indicates the IP address and port where
//   responses would have been sent from if the "change IP" and "change
//   port" flags had been set in the CHANGE-REQUEST attribute of the
//   Binding Request.  The attribute is always present in a Binding
//   Response, independent of the value of the flags.  Its syntax is
//   identical to MAPPED-ADDRESS.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct ChangedAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl ChangedAddress {
    pub fn new(family: u8, port: u16, address: Ipv4Addr) -> Self {
        ChangedAddress {
            family: family,
            port: port,
            address: address
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = parse_addr(i) {
            Some(
                Self::new(family, port, Ipv4Addr::new(address[0], address[1], address[2], address[3]))
            )
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(self.family)?;
        wtr.write_u16::<BigEndian>(self.port)?;
        let addr = unsafe { mem::transmute::<[u8;4], u32>(self.address.octets()) };
        wtr.write_u32::<BigEndian>(addr)?;
        Ok(wtr)
    }
}

#[test]
fn test_enc_dec_change_address() {
    let map = ChangedAddress::new(1, 5000, Ipv4Addr::new(192, 168, 1, 1));
    let binary = map.encode().unwrap();
    let map2 = ChangedAddress::decode(&binary);
    assert_eq!(Some(map), map2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct ChangeRequest {
    a: bool,
    b: bool,
}

impl ChangeRequest {
    pub fn new(a: bool, b: bool) -> Self {
        ChangeRequest {
            a: a,
            b: b
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (a, b))) = ChangeRequest::parse(i) {
            Some(Self::new(a, b))
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut flag = 0u8;
        if self.a {
            flag |= 4;
        }
        if self.b {
            flag |= 2;
        }
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(0)?;
        wtr.write_u8(0)?;
        wtr.write_u8(flag).unwrap();
        Ok(wtr)
    }

    fn parse(i: &[u8]) -> IResult<&[u8], (bool, bool)> {
        do_parse!(i,
            _x: take!(3)
            >> last_byte: bits!(tuple!(take_bits!(u8, 5), take_bits!(u8, 1), take_bits!(u8, 1), take_bits!(u8, 1)))
            >> (
                last_byte.1 == 1, last_byte.2 == 1
               )
        )
    }
}

#[test]
fn test_enc_dec_change_request_true_true() {
    let change_req = ChangeRequest::new(true, true);
    let binary = change_req.encode().unwrap();
    let change_req2 = ChangeRequest::decode(&binary);
    assert_eq!(Some(change_req), change_req2);
}

#[test]
fn test_enc_dec_change_request_true_false() {
    let change_req = ChangeRequest::new(true, false);
    let binary = change_req.encode().unwrap();
    let change_req2 = ChangeRequest::decode(&binary);
    assert_eq!(Some(change_req), change_req2);
}

#[test]
fn test_enc_dec_change_request_false_true() {
    let change_req = ChangeRequest::new(false, true);
    let binary = change_req.encode().unwrap();
    let change_req2 = ChangeRequest::decode(&binary);
    assert_eq!(Some(change_req), change_req2);
}

#[test]
fn test_enc_dec_change_request_false_false() {
    let change_req = ChangeRequest::new(false, false);
    let binary = change_req.encode().unwrap();
    let change_req2 = ChangeRequest::decode(&binary);
    assert_eq!(Some(change_req), change_req2);
}

// 11.2.5 SOURCE-ADDRESS
//
//   The SOURCE-ADDRESS attribute is present in Binding Responses.  It
//   indicates the source IP address and port that the server is sending
//   the response from.  Its syntax is identical to that of MAPPED-
//   ADDRESS.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct SourceAddress {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl SourceAddress {
    pub fn new(family: u8, port: u16, address: Ipv4Addr) -> Self {
        SourceAddress {
            family: family,
            port: port,
            address: address
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = parse_addr(i) {
            Some(
                Self::new(family, port, Ipv4Addr::new(address[0], address[1], address[2], address[3]))
            )
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(self.family)?;
        wtr.write_u16::<BigEndian>(self.port)?;
        let addr = unsafe { mem::transmute::<[u8;4], u32>(self.address.octets()) };
        wtr.write_u32::<BigEndian>(addr)?;
        Ok(wtr)
    }
}

#[test]
fn test_enc_dec_source_address() {
    let map = SourceAddress::new(1, 5000, Ipv4Addr::new(192, 168, 1, 1));
    let binary = map.encode().unwrap();
    let map2 = SourceAddress::decode(&binary);
    assert_eq!(Some(map), map2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct UserName {
    user_name: String
}

impl UserName {
    pub fn new(user_name: String) -> Self {
        UserName {
            user_name: user_name
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        match String::from_utf8(i.to_vec()) {
            Ok(x) => Some(Self::new(x)),
            Err(e) => None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        Ok(self.user_name.clone().into_bytes())
    }
}

#[test]
fn test_enc_dec_user_name() {
    let user = UserName { user_name: "hoge".to_string() };
    let binary = user.encode().unwrap();
    let user2 = UserName::decode(&binary);
    assert_eq!(Some(user), user2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct Password {
    password: String
}

impl Password {
    pub fn new(password: String) -> Self {
        Password {
            password: password
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        match String::from_utf8(i.to_vec()) {
            Ok(x) => Some(Self::new(x)),
            Err(e) => None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        Ok(self.password.clone().into_bytes())
    }
}

#[test]
fn test_enc_dec_password() {
    let passwd = Password { password: "passwd".to_string() };
    let binary = passwd.encode().unwrap();
    let passwd2 = Password::decode(&binary);
    assert_eq!(Some(passwd), passwd2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct MessageIntegrity {
    hmac: String
}

impl MessageIntegrity {
    pub fn new(hmac: String) -> Self {
        MessageIntegrity {
            hmac: hmac
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        match String::from_utf8(i.to_vec()) {
            Ok(x) => Some(Self::new(x)),
            Err(e) => None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        Ok(self.hmac.clone().into_bytes())
    }
}

#[test]
fn test_enc_dec_integrity() {
    let integrity = MessageIntegrity { hmac: "hmac".to_string() };
    let binary = integrity.encode().unwrap();
    let integrity2 = MessageIntegrity::decode(&binary);
    assert_eq!(Some(integrity), integrity2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct ErrorCode {
    class: u8,
    number: u8,
    reason: String,
}

impl ErrorCode {
    pub fn new(class: u8, number: u8, reason: String) -> Self {
        ErrorCode {
            class: class,
            number: number,
            reason: reason
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (class, number, reason))) = ErrorCode::parse(i) {
            match String::from_utf8(reason.to_vec()) {
                Ok(x) => Some(Self::new(class, number, x)),
                Err(_e) => None,
            }
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(0)?;
        wtr.write_u8(self.class)?;
        wtr.write_u8(self.number)?;
        wtr.extend_from_slice(&self.reason.as_bytes());
        Ok(wtr)
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

#[test]
fn test_enc_dec_error_code() {
    let error = ErrorCode::new(1, 1, "hoge".to_string());
    let binary = error.encode().unwrap();
    let error2 = ErrorCode::decode(&binary);
    assert_eq!(Some(error), error2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct Unknown {
    attributes: Vec<u16>
}

impl Unknown {
    pub fn new(attributes: Vec<u16>) -> Self {
        Unknown {
            attributes: attributes
        }
    }

    pub fn decode(i: &[u8]) -> Self {
        let iter = UnknownIter { buf: i.to_vec() };
        let vec: Vec<u16> = iter.collect();
        Self::new(vec)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr: Vec<u8> = vec!();
        for x in self.attributes.iter() {
            wtr.write_u16::<BigEndian>(*x)?;
        }
        Ok(wtr)
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

#[test]
fn test_enc_dec_unknown() {
    let unknown = Unknown::new(vec!(1, 2, ::std::u16::MAX));
    let binary = unknown.encode().unwrap();
    let unknown2 = Unknown::decode(&binary);
    assert_eq!(unknown, unknown2);
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
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub struct ReflectedFrom {
    family: u8,
    port: u16,
    address: Ipv4Addr,
}

impl ReflectedFrom {
    pub fn new(family: u8, port: u16, address: Ipv4Addr) -> Self {
        ReflectedFrom {
            family: family,
            port: port,
            address: address
        }
    }

    pub fn decode(i: &[u8]) -> Option<Self> {
        if let Ok((_, (family, port, address))) = parse_addr(i) {
            Some(
                Self::new(family, port, Ipv4Addr::new(address[0], address[1], address[2], address[3]))
            )
        } else {
            None
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        wtr.write_u8(self.family)?;
        wtr.write_u16::<BigEndian>(self.port)?;
        let addr = unsafe { mem::transmute::<[u8;4], u32>(self.address.octets()) };
        wtr.write_u32::<BigEndian>(addr)?;
        Ok(wtr)
    }
}

#[test]
fn test_enc_dec_reflect_from() {
    let reflect = ReflectedFrom::new(1, 5000, Ipv4Addr::new(192, 168, 1, 1));
    let binary = reflect.encode().unwrap();
    let reflect2 = ReflectedFrom::decode(&binary);
    assert_eq!(Some(reflect), reflect2);

}

