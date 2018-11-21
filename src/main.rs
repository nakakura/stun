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

fn send_change_request(socket_addr: &SocketAddr, remote_addr: &SocketAddr, change_ip_flag: bool, change_port_flag: bool) -> Result<SocketAddr, ()> {
    let socket = UdpSocket::bind(socket_addr).unwrap();
    let when = Instant::now() + Duration::from_millis(100);
    let mut runtime = Runtime::new().unwrap();

    let task = Delay::new(when)
        .map_err(|e| panic!("timer failed; err={:?}", e))
        .and_then(|_| {
            let change_request_internal = message::attributes::ChangeRequest::new(change_ip_flag, change_port_flag);
            let change_request = message::Attribute::ChangeRequest(change_request_internal);
            let message = message::StunMessage::create_from_attributes(1, vec!(change_request));
            socket.send_dgram(message.encode().unwrap(), remote_addr)
        })
        .and_then(|(socket, _)| {
            socket.recv_dgram(vec![0u8; MAX_DATAGRAM_SIZE])
        }).map_err(|_| ())
        .and_then(|(_socket, data, _len, _send_from)| {
            let message = message::StunMessage::decode(&data).unwrap();
            if let message::Attribute::MappedAddress(ref mapped) = message.attributes[0] {
                let socket_addr = ::std::net::SocketAddr::new(IpAddr::V4(mapped.address), mapped.port);
                Ok(socket_addr)
            } else {
                Err(())
            }
        });

    runtime.block_on(task)
}

fn step1(socket_addr: &SocketAddr, remote_addr: &SocketAddr) {
    let result = send_change_request(&socket_addr, &remote_addr, false, false);
    if result.is_err() {
        println!("UDP Blocked");
        return;
    }
    let mapped_addr = result.unwrap();

    step2(socket_addr, remote_addr, mapped_addr);
}

fn step2(socket_addr: &SocketAddr, remote_addr: &SocketAddr, mapped_addr: SocketAddr) {
    let result = send_change_request(socket_addr, remote_addr, true, true);
    if result.is_ok() {
        if *socket_addr == mapped_addr {
            println!("Open Internet");
        } else {
            println!("Full Cone");
        }
    } else {
        if *socket_addr == mapped_addr {
            println!("Symmetric UDP Firewall");
        } else {
            step3(socket_addr, remote_addr, mapped_addr);
        }
    }
}

fn step3(socket_addr: &SocketAddr, remote_addr: &SocketAddr, mapped_addr: SocketAddr) {
    let mapped_addr_2 = send_change_request(socket_addr, remote_addr, false, false).unwrap();
    if mapped_addr != mapped_addr_2 {
        println!("Symmetric NAT")
    } else {
        let result = send_change_request(socket_addr, remote_addr, false, true);
        if result.is_ok() {
            println!("Restricted NAT");
        } else {
            println!("Port Restricted NAT");
        }
    }
}

fn main() {
    let remote_addrs: Vec<_> = "stun.l.google.com:19302".to_socket_addrs()
        .expect("Unable to resolve domain")
        .filter(|x| x.is_ipv4())
        .collect();
    let local_socket_addr = (|| {
        println!("please specify nic with id");
        let ifaces: Vec<_> = datalink::interfaces().iter().flat_map(|x| x.ips.clone()).filter(|x| x.is_ipv4()).collect();
        for (id, iface) in (&ifaces).iter().enumerate() {
            println!("{}: {:?}", id, iface);
        }

        let mut input = String::new();
        let ip_addr_opt = match ::std::io::stdin().read_line(&mut input) {
            Ok(_) => {
                let id = input.trim().parse::<usize>().expect("input number");
                Some(ifaces.get(id)?.ip())
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

    step1(&local_socket_addr, &remote_addrs[0]);
}
