extern crate futures;
extern crate tokio;
extern crate nom;
#[cfg(test)]
extern crate hex;
extern crate byteorder;
extern crate rand;
#[macro_use]
extern crate lazy_static;
extern crate pnet;

mod message;

use std::net::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pnet::datalink;
use tokio::net::UdpSocket;
use tokio::prelude::*;
use tokio::timer::Delay;
use tokio::runtime::current_thread::Runtime;

lazy_static! {
  static ref NAT_ADDR: Mutex<Option<Ipv4Addr>> = Mutex::new(None);
  static ref NAT_PORT: Mutex<Option<u16>> = Mutex::new(None);
  static ref BEHIND_NAT: Mutex<bool> = Mutex::new(false);
}

const MAX_DATAGRAM_SIZE: usize = 1500;

fn task1(socket: UdpSocket, remote_addr: &SocketAddr) -> UdpSocket {
    let mut runtime = Runtime::new().unwrap();
    let when = Instant::now() + Duration::from_millis(100);

    let task = Delay::new(when)
        .map_err(|e| panic!("timer failed; err={:?}", e))
        .and_then(|_| {
            let change_request_internal = message::attributes::ChangeRequest::new(false, false);
            let change_request = message::Attribute::ChangeRequest(change_request_internal);
            let message = message::StunMessage::create_from_attributes(1, vec!(change_request));
            socket.send_dgram(message.encode().unwrap(), remote_addr)
        })
        .and_then(|(socket, _)| {
            socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE])
        })
        .and_then(|(socket, data, _len, _send_from)| {
            let local_addr: SocketAddr = socket.local_addr().unwrap();
            let message = message::StunMessage::decode(&data).unwrap();
            if let message::Attribute::MappedAddress(ref mapped) = message.attributes[0] {
                {
                    if let (Some(ref addr), Some(ref port)) = (*(NAT_ADDR.lock().unwrap()), *(NAT_PORT.lock().unwrap())) {
                        if addr != &mapped.address || port != &mapped.port {
                            println!("synmetric");
                            ::std::process::exit(0);
                        }
                    }
                }
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
            Ok(socket)
        });

    match runtime.block_on(task) {
        Ok(socket) => socket,
        Err(e) => {
            println!("{:?}", e);
            ::std::process::exit(0);
        }
    }
}

fn task2(socket: UdpSocket, remote_addr: &SocketAddr) -> Result<UdpSocket, ::std::io::Error> {
    let mut runtime = Runtime::new().unwrap();
    let when = Instant::now() + Duration::from_millis(100);

    let task = Delay::new(when)
        .map_err(|e| panic!("timer failed; err={:?}", e))
        .and_then(|_| {
            let change_request_internal = message::attributes::ChangeRequest::new(true, true);
            let change_request = message::Attribute::ChangeRequest(change_request_internal);
            let message = message::StunMessage::create_from_attributes(1, vec!(change_request));
            socket.send_dgram(message.encode().unwrap(), remote_addr)
        })
        .and_then(|(socket, _)| {
            socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE])
        })
        .and_then(|(socket, data, _len, _send_from)| {
            let local_addr: SocketAddr = socket.local_addr().unwrap();
            let message = message::StunMessage::decode(&data).unwrap();
            if let message::Attribute::MappedAddress(ref mapped) = message.attributes[0] {
                *(NAT_ADDR.lock().unwrap()) = Some(mapped.address);
                *(NAT_PORT.lock().unwrap()) = Some(mapped.port);

                if *(BEHIND_NAT.lock().unwrap()) {
                    println!("full corn");
                } else {
                    println!("direct connection to internet");
                }
            }
            Ok(socket)
        });

    runtime.block_on(task)
}

fn task3(socket: UdpSocket, remote_addr: &SocketAddr) -> Result<UdpSocket, ::std::io::Error> {
    let mut runtime = Runtime::new().unwrap();
    let when = Instant::now() + Duration::from_millis(100);

    let task = Delay::new(when)
        .map_err(|e| panic!("timer failed; err={:?}", e))
        .and_then(|_| {
            let change_request_internal = message::attributes::ChangeRequest::new(true, true);
            let change_request = message::Attribute::ChangeRequest(change_request_internal);
            let message = message::StunMessage::create_from_attributes(1, vec!(change_request));
            socket.send_dgram(message.encode().unwrap(), remote_addr)
        })
        .and_then(|(socket, _)| {
            socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE])
        })
        .and_then(|(socket, data, _len, _send_from)| {
            let local_addr: SocketAddr = socket.local_addr().unwrap();
            let message = message::StunMessage::decode(&data).unwrap();
            if let message::Attribute::MappedAddress(ref mapped) = message.attributes[0] {
                println!("restricted");
                ::std::process::exit(1);
            }
            Ok(socket)
        });

    runtime.block_on(task)
}

fn main() {
    let local_socket_addr = (|| {
        println!("please specify nic with id");
        let ifaces = datalink::interfaces();
        for (id, iface) in (&ifaces).iter().enumerate() {
            println!("{}: {:?}", id, iface.ips);
        }

        let mut input = String::new();
        let ip_addr_opt = match ::std::io::stdin().read_line(&mut input) {
            Ok(n) => {
                let id = input.trim().parse::<usize>().expect("input number");
                ifaces.get(id)?.ips.iter().find(|x| x.is_ipv4()).map(|x| x.ip())
            },
            Err(error) => {
                println!("error: {}", error);
                None
            }
        };
        ip_addr_opt.map(|ip_addr| {
            let socket_addr = ::std::net::SocketAddr::new(ip_addr, 0);
            let socket = UdpSocket::bind(&socket_addr).unwrap();
            socket.local_addr().unwrap()
        })
    })().expect("Please Select valid NIC");

    let server_details = "stun.l.google.com:19302";
    let remote_addr: Vec<_> = server_details.to_socket_addrs()
        .expect("Unable to resolve domain")
        .collect();
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let port = local_addr.port();
    let socket = UdpSocket::bind(&local_addr).unwrap();
    let socket = task1(socket, &remote_addr[0]);
    let result = task2(socket, &remote_addr[0]);
    result.map_err(|_| {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let socket = UdpSocket::bind(&local_addr).unwrap();
        let socket = task1(socket, &remote_addr[0]);
        let result = task3(socket, &remote_addr[0]);
        result.map_err(|_| println!("port restricted") )
    });



/*
        let change_request_internal = message::attributes::ChangeRequest::new(true, false);
        let change_request = message::Attribute::ChangeRequest(change_request_internal);
        let message = message::StunMessage::create_from_attributes(1, vec!(change_request));

        socket.send_dgram(message.encode().unwrap(), &remote_addr[0])
        */





    /*
    let processing = socket
        .send_dgram(message.encode().unwrap(), &remote_addr[0])


        .and_then(|(socket, _)| socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE]))
        .map(|(socket, data, len, _)| {

        })
        .wait();
    match processing {
        Ok(_) => {}
        Err(e) => eprintln!("Encountered an error: {}", e),
    }

*/


}

