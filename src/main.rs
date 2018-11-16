extern crate futures;
extern crate tokio;
extern crate nom;
#[cfg(test)]
extern crate hex;
extern crate byteorder;
extern crate rand;
#[macro_use]
extern crate lazy_static;

mod message;

use std::net::*;
use std::sync::Mutex;

use tokio::net::UdpSocket;
use tokio::prelude::*;

lazy_static! {
  static ref NAT_ADDR: Mutex<Option<Ipv4Addr>> = Mutex::new(None);
  static ref NAT_PORT: Mutex<Option<u16>> = Mutex::new(None);
  static ref BEHIND_NAT: Mutex<bool> = Mutex::new(false);
}

fn main() {
    let server_details = "stun.l.google.com:19302";
    let remote_addr: Vec<_> = server_details.to_socket_addrs()
        .expect("Unable to resolve domain")
        .collect();

    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let socket = UdpSocket::bind(&local_addr).unwrap();

    const MAX_DATAGRAM_SIZE: usize = 1500;
    let change_request_internal = message::attributes::ChangeRequest::new(false, false);
    let change_request = message::Attribute::ChangeRequest(change_request_internal);
    let message = message::StunMessage::create_from_attributes(1, vec!(change_request));

    let processing = socket
        .send_dgram(message.encode().unwrap(), &remote_addr[0])
        .and_then(|(socket, _)| {
            socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE])
        })
        .and_then(|(socket, data, len, _send_from)| {
            println!("{:?}", _send_from);
            let local_addr: SocketAddr = socket.local_addr().unwrap();
            let message = message::StunMessage::decode(&data).unwrap();
            if let message::Attribute::MappedAddress(ref mapped) = message.attributes[0] {
                *(NAT_ADDR.lock().unwrap()) = Some(mapped.address);
                *(NAT_PORT.lock().unwrap()) = Some(mapped.port);

                // FIXME: local_addr.ip() returns 0.0.0.0. It's meaningless
                if local_addr.ip() == mapped.address && local_addr.port() == mapped.port {
                    println!("not behind nat");
                    *(BEHIND_NAT.lock().unwrap()) = false;
                } else {
                    println!("behind nat");
                    *(BEHIND_NAT.lock().unwrap()) = true;
                }
            }

            let change_request_internal = message::attributes::ChangeRequest::new(true, false);
            let change_request = message::Attribute::ChangeRequest(change_request_internal);
            let message = message::StunMessage::create_from_attributes(1, vec!(change_request));

            socket.send_dgram(message.encode().unwrap(), &remote_addr[0])
        })
        .and_then(|(socket, _)| socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE]))
        .map(|(socket, data, len, _)| {
            if *(BEHIND_NAT.lock().unwrap()) {
                println!("full corn");
            } else {
                println!("direct connection to internet");
            }
        })
        .wait();
    match processing {
        Ok(_) => {}
        Err(e) => eprintln!("Encountered an error: {}", e),
    }




}

