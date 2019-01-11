#![feature(int_to_from_bytes)]

use std::str::FromStr;
use std::mem;
use std::net::*;

use byteorder::{BigEndian, WriteBytesExt};
use nom::*;
use stringprep;

use super::error;

// 15.1.  MAPPED-ADDRESS
//
//   The MAPPED-ADDRESS attribute indicates a reflexive transport address
//   of the client.  It consists of an 8-bit address family and a 16-bit
//   port, followed by a fixed-length value representing the IP address.
//   If the address family is IPv4, the address MUST be 32 bits.  If the
//   address family is IPv6, the address MUST be 128 bits.  All fields
//   must be in network byte order.
//
//   The format of the MAPPED-ADDRESS attribute is:
//
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |0 0 0 0 0 0 0 0|    Family     |           Port                |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      |                 Address (32 bits or 128 bits)                 |
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//               Figure 5: Format of MAPPED-ADDRESS Attribute
//
//   The address family can take on the following values:
//
//   0x01:IPv4
//   0x02:IPv6
//
//   The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
//   ignored by receivers.  These bits are present for aligning parameters
//   on natural 32-bit boundaries.
//
//   This attribute is used only by servers for achieving backwards
//   compatibility with RFC 3489 [RFC3489] clients.

// Addressは可変長であり、Familyの値を見ないと長さが分からないため、
// まず固定長のフィールドだけ先に取り出すマクロ
named!(mapped_address_fixed_headers_raw_value<(u8, u8, u16)>, do_parse!(
    head: be_u8
    >> family: be_u8
    >> port: be_u16
    >> (head, family, port) //The remaining data is an address
  )
);

// バイト列からMAPPED-ADDRESSに必要なフィールドを取り出す
// この時点では単に生値として取り出すので、XOR-MAPPED-ADDRESSでも参照する
fn mapped_address_header_raw_values(i: &[u8]) -> Result<(&[u8], (u8, TransportAddrSource)), error::ErrorEnum> {
    let (i, (head, family, port)) = mapped_address_fixed_headers_raw_value(i)?;
    match family {
        1 => take!(i, 4).map(|(i, addr_source)| {
            //ipv4 addrはu8が並んでいるためEndianの影響を受けず、そのまま利用できる
            let mut array = [0u8; 4];
            array.copy_from_slice(&addr_source[0..4]);
            Ok((
                i,
                (head, TransportAddrSource::V4((array, port)))
            ))
        })?,
        n => be_u128(i).map(|(i, addr_value)| {
            //ipv6 addrはu16が並んでいるため、ab, cd, ef, gh, ij, kl, mn, opと値が入っている
            //u8として取り出すとdecodeが大変なので、u128で切り出してtransmuteでu16 arrayにする
            //これにより、op, mn, kl, ij, gh, ef, cd, abと並ぶので、reverseしてやればよい
            let mut hextets = unsafe { mem::transmute::<u128, [u16; 8]>(addr_value) };
            hextets.reverse();
            let mut array = [0u16; 8];
            array.copy_from_slice(&hextets[0..8]);
            Ok((
                i,
                (head, TransportAddrSource::V6((array, port)))
            ))
        })?,
    }
}

// 取り出したバイト列をIPアドレスに変換するための処理をまとめておく
#[derive(Clone, Debug, PartialOrd, PartialEq)]
pub enum TransportAddrSource {
    V4(([u8;4], u16)),
    V6(([u16;8], u16)),
}

impl TransportAddrSource {
    pub fn new(addr: IpAddr, port: u16) -> Self {
        match addr {
            IpAddr::V4(addr) => {
                TransportAddrSource::V4((addr.octets(), port))
            },
            IpAddr::V6(addr) => {
                TransportAddrSource::V6((addr.segments(), port))
            }
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TransportAddrSource::V4((_, p)) => *p,
            TransportAddrSource::V6((_, p)) => *p,
        }
    }

    pub fn address(&self) -> IpAddr {
        match self {
            TransportAddrSource::V4((source, _)) => {
                IpAddr::V4(Ipv4Addr::new(source[0], source[1], source[2], source[3]))
            },
            TransportAddrSource::V6((source, _)) => {
                IpAddr::V6(Ipv6Addr::new(
                    source[0], source[1],
                    source[2], source[3],
                    source[4], source[5],
                    source[6], source[7],
                ))
            },
        }
    }

    pub fn xor(self, transaction_id: [u8;16]) -> Self {
        // portはBig EndianとしてLittle Endianのマシンに読み込み済みである
        // Magic CookieはBig Endianのままなので逆順にしてXORする
        let mut magic_cookie_port_src = [0u8;2];
        magic_cookie_port_src[0] = transaction_id[1];
        magic_cookie_port_src[1] = transaction_id[0];
        let mut magic_cookie_port = unsafe { mem::transmute::<[u8;2], u16>(magic_cookie_port_src) };

        // u8列なのでEndian関係なくこのまま使える
        let magic_cookie_ipv4 = &transaction_id[0..4];
        // このままだとBig Endianのまま並んでいる
        let mut magic_cookie_ipv6 = unsafe { mem::transmute::<[u8;16], [u16;8]>(transaction_id) };

        match self {
            TransportAddrSource::V4((address, port)) => {
                let mut xor_address = [0u8;4];
                for (i, value) in address.iter().enumerate() {
                    xor_address[i] = value ^ magic_cookie_ipv4[i];
                }

                let xor_port = port ^ magic_cookie_port;

                TransportAddrSource::V4((xor_address, xor_port))
            },
            TransportAddrSource::V6((address, port)) => {
                let mut xor_address = [0u16;8];
                for (i, values) in (&magic_cookie_ipv6).iter().zip(&address).enumerate() {
                    // Little Endianに変換してからXORする
                    xor_address[i] = u16::from_be(*values.0) ^ values.1;
                }

                let xor_port = port ^ magic_cookie_port;

                TransportAddrSource::V6((xor_address, xor_port))
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MappedAddress(SocketAddr);

impl MappedAddress {
    pub fn decode(i: &[u8]) -> Result<Self, error::ErrorEnum> {
        let (i, (head, addr_source)) = mapped_address_header_raw_values(i)?;
        if head != 0 {
            // headは0であるはずなのでチェックする
            return Err(error::ErrorEnum::MyError{ error: "it's not a stun packet".to_string() });
        } else if i.len() > 0 {
            // IPアドレスまで取得してもデータが残っている場合、
            // IPv6アドレスなのにIPv4として32bitだけ取っているような場合や
            // そもそもMAPPED-ADDRESS Attributeではない場合が考えられる
            return Err(error::ErrorEnum::MyError{ error: "wrong addr family".to_string() });
        }


        let addr = addr_source.address();
        let port = addr_source.port();
        let sock_addr = match addr {
            IpAddr::V4(addr) => {
                SocketAddr::V4(SocketAddrV4::new(addr, port))
            },
            IpAddr::V6(addr) => {
                SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0))
            }
        };
        Ok(MappedAddress(sock_addr))
    }

    pub fn encode(&self) -> Result<Vec<u8>, error::ErrorEnum> {
        let mut wtr = vec![];
        wtr.write_u8(0)?;
        match self {
            MappedAddress(SocketAddr::V4(addr)) => {
                wtr.write_u8(1)?; //IPv4 family
                wtr.write_u16::<BigEndian>(addr.port())?;
                // 8bit単位なのでEndian気にせず単純に前から書く
                for byte in addr.ip().octets().iter() {
                    wtr.write_u8(*byte)?;
                }
            },
            MappedAddress(SocketAddr::V6(addr)) => {
                wtr.write_u8(2)?; //IPv6 family
                wtr.write_u16::<BigEndian>(addr.port())?;
                //octets = 8bitごとに出力されるので、ponmlkjihgfedcbaの順のArray
                //必要なのは16bitのbig endian数値の列(ab, cd, ef, gh, ij, kl, mn, op)
                //u8単位で1つずつ書き込んでやると合致する
                for byte in addr.ip().octets().iter() {
                    wtr.write_u8(*byte)?;
                }
            },
        }
        Ok(wtr)
    }
}

#[test]
fn test_enc_dec_mapped_address_v4_ok() {
    let sock_addr = SocketAddr::V4(SocketAddrV4::new("192.168.2.1".parse().unwrap(), 5000));
    let mapped_address = MappedAddress(sock_addr);
    let binary = mapped_address.encode().unwrap();
    let decoded_address = MappedAddress::decode(&binary);
    assert_eq!(Ok(mapped_address), decoded_address);
}

#[test]
fn test_enc_dec_mapped_address_v6_ok() {
    let sock_addr = SocketAddr::V6(SocketAddrV6::new("2402:c800:ff46::2c59".parse().unwrap(), 5000, 0, 0));
    let mapped_address = MappedAddress(sock_addr);
    let binary = mapped_address.encode().unwrap();
    let decoded_address = MappedAddress::decode(&binary);
    assert_eq!(Ok(mapped_address), decoded_address);
}

#[test]
fn test_dec_mapped_address_real_data_v4() {
    let vec = hex::decode("0001cc0e3dcf49d4").unwrap();
    let MappedAddress(decoded_address) = MappedAddress::decode(&vec).unwrap();
    assert_eq!(52238, decoded_address.port());
    let addr: IpAddr = "61.207.73.212".parse().unwrap();
    assert_eq!(addr, decoded_address.ip());
}

#[test]
fn test_dec_mapped_address_fail_non_zero_family_v4() {
    let vec = hex::decode("1001cc0e3dcf49d4").unwrap();
    let decoded_address = MappedAddress::decode(&vec);
    assert!(decoded_address.is_err());
}

#[test]
fn test_dec_mapped_address_fail_wrong_address_family_v4() {
    let vec = hex::decode("0002cc0e3dcf49d4").unwrap();
    let decoded_address = MappedAddress::decode(&vec);
    assert!(decoded_address.is_err());
}

#[test]
fn test_dec_mapped_address_real_data_v6() {
    //2400:4070:347:c00:4168:fac4:701b:904d, port: 57852
    let vec = hex::decode("0002e1fc2400407003470c004168fac4701b904d").unwrap();
    let MappedAddress(decoded_address) = MappedAddress::decode(&vec).unwrap();
    assert_eq!(57852, decoded_address.port());
    let addr: IpAddr = "2400:4070:347:c00:4168:fac4:701b:904d".parse().unwrap();
    assert_eq!(addr, decoded_address.ip());
}

#[test]
fn test_dec_mapped_address_fail_non_zero_family_v6() {
    let vec = hex::decode("1000e1fc2400407003470c004168fac4701b904d").unwrap();
    let decoded_address = MappedAddress::decode(&vec);
    assert!(decoded_address.is_err());
}

#[test]
fn test_dec_mapped_address_fail_wrong_address_family_v6() {
    let vec = hex::decode("0001e1fc2400407003470c004168fac4701b904d").unwrap();
    let decoded_address = MappedAddress::decode(&vec);
    assert!(decoded_address.is_err());
}