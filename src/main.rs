use std::net::SocketAddr;
use std::sync::Arc;

use nom::AsBytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;

use dns::{dns_msg, response, Writeable};

mod dns;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = "127.0.0.1:2053";
    let sock = UdpSocket::bind(addr).await?;

    println!("INFO: listening on {addr}");

    let receiver = Arc::new(sock);
    let sender = receiver.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    tokio::spawn(async move {
        response_handler(sender, rx).await;
    });

    // listening for new requests
    let mut buf = [0u8; 1024];
    loop {
        let (len, addr) = match receiver.recv_from(&mut buf).await {
            Ok(values) => values,
            Err(err) => {
                println!("ERROR: failed to read from socket with {err}");
                continue;
            }
        };
        println!("{:?} bytes received from {:?}", len, addr);
        if let Err(err) = tx.send((buf[..len].to_vec(), addr)).await {
            println!("ERROR: failed to send to channel with {err}");
        }
    }
}

async fn response_handler(sender: Arc<UdpSocket>, mut rx: Receiver<(Vec<u8>, SocketAddr)>) {
    while let Some((bytes, addr)) = rx.recv().await {
        let req = match dns_msg(bytes.as_slice()) {
            Ok((_, a)) => {
                println!("DEBUG: got header {a:?}");
                a
            }
            Err(err) => {
                eprintln!("ERROR: failed to parse - '{err}'");
                continue;
            }
        };

        let response = response(&req);

        let mut buff: Vec<u8> = Vec::new();
        if response.write(&mut buff).is_ok() {
            match sender.send_to(buff.as_bytes(), &addr).await {
                Ok(len) => {
                    println!("INFO response with {:?} bytes", len);
                }
                Err(err) => {
                    println!("ERROR: failed to write to socket with {err}");
                }
            }
        };
    }
}
