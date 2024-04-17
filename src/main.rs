use std::net::SocketAddr;
use std::sync::Arc;

use nom::{AsChar, InputTake, IResult, number::complete::{be_u16, be_u8}};
use nom::bytes::complete::take;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

enum QR {
    Query,
    Response,
}

enum OPCODE {
    Null
}

enum RCODE {
    NoError,
}

#[derive(Debug)]
struct DnsLabels(Vec<String>);

impl DnsLabels {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in self.0.iter() {
            bytes.extend((label.len() as u8).to_be_bytes());
            bytes.extend(label.as_bytes());
        }
        bytes.extend(0_u8.to_be_bytes());
        println!("DEBUG: labels {bytes:?\
        }");
        bytes
    }
}

#[derive(Debug)]
struct DnsQuestion {
    labels: DnsLabels,
    q_type: u16,
    class: u16,
}

impl DnsQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(&self.labels.to_bytes());
        bytes.extend(&self.q_type.to_be_bytes());
        bytes.extend(&self.class.to_be_bytes());
        bytes
    }
}

#[derive(Debug)]
struct DnsHeader {
    // 2 bytes
    id: u16,
    // 1bit
    qr: u8,
    // 4bits
    opcode: u8,
    // 1bit
    aa: u8,
    // 1bit
    tc: u8,
    // 1bit
    rd: u8,
    // 1bit
    ra: u8,
    // 3bits
    z: u8,
    // 4bit
    rcode: u8,
    // 2 bytes
    qdcount: u16,
    // 2 bytes
    ancount: u16,
    // 2 bytes
    nscount: u16,
    // 2 bytes
    arcount: u16,
}

impl DnsHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(&self.id.to_be_bytes());
        bytes.push((self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd);
        bytes.push((self.ra << 7) | (self.z << 4) | self.rcode);
        bytes.extend(&self.qdcount.to_be_bytes());
        bytes.extend(&self.ancount.to_be_bytes());
        bytes.extend(&self.nscount.to_be_bytes());
        bytes.extend(&self.arcount.to_be_bytes());

        bytes
    }
}

#[derive(Debug)]
struct DnsMessage {
    header: DnsHeader,
    question: Option<DnsQuestion>,
}

impl DnsMessage {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.header.to_bytes());
        if let Some(question) = &self.question {
            bytes.extend(question.to_bytes());
        }


        bytes
    }
}

type BitInput<'a> = (&'a [u8], usize);


fn dns_header(input: &[u8]) -> IResult<(&[u8]), DnsHeader> {
    let (input, id) = be_u16(input)?;
    let (input, qr) = be_u8(input)?;
    let (input, opcode) = take(4usize)(input)?;
    let (input, aa) = take(1usize)(input)?;
    let (input, tc) = take(1usize)(input)?;
    let (input, rd) = take(1usize)(input)?;
    let (input, ra) = take(1usize)(input)?;
    let (input, z) = take(3usize)(input)?;
    let (input, rcode) = take(4usize)(input)?;
    let (input, qdcount) = be_u16(input)?;
    let (input, ancount) = be_u16(input)?;
    let (input, nscount) = be_u16(input)?;
    let (input, arcount) = be_u16(input)?;
    let header = DnsHeader {
        id,
        qr,
        opcode: opcode[0],
        aa: aa[0],
        tc: tc[0],
        rd: rd[0],
        ra: ra[0],
        z: z[0],
        rcode: rcode[0],
        qdcount,
        ancount,
        nscount,
        arcount,
    };

    Ok((input, header))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = "127.0.0.1:2053";
    let sock = UdpSocket::bind(addr).await?;

    println!("INFO: listening on {addr}");

    let receiver = Arc::new(sock);
    let sender = receiver.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    tokio::spawn(async move {
        // response actor
        while let Some((bytes, addr)) = rx.recv().await {
            let a = dns_header(&bytes.as_slice());
            let req = if let Ok((_, a)) = a {
                println!("DEBUG: got header {a:?}");
                a
            } else {
                continue;
            };
            // match a {
            //     Ok((left, x)) => {
            //
            //         println!("DEBUG: left {left:?}");
            //     }
            //     Err(err) => {
            //         // Err(anyhow!("ERROR: failed parsing dns header with '{err}'"))?
            //     }
            // }
            let response =
                DnsMessage {
                    header: DnsHeader
                    {
                        id: req.id,
                        qr: 0,
                        opcode: 0,
                        aa: 0,
                        tc: 0,
                        rd: 0,
                        ra: 0,
                        z: 0,
                        rcode: 0,
                        qdcount: 0,
                        ancount: 0,
                        nscount: 0,
                        arcount: 0,
                    },
                    question: Some(
                        DnsQuestion {
                            labels: DnsLabels(
                                vec![
                                    "codecrafters".to_string(),
                                    "io".to_string(),
                                ]),
                            q_type: 1,
                            class: 1,
                        }
                    ),
                };
            println!("DEBUG: response {response:?}");
            println!("DEBUG: response as bytes {:?}", response.to_bytes());
            match sender.send_to(&response.to_bytes(), &addr).await {
                Ok(len) => {
                    println!("INFO response with {:?} bytes", len);
                }
                Err(err) => {
                    println!("ERROR: failed to write to socket with {err}");
                }
            }
        }
    });

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

#[cfg(test)]
mod test {
    use crate::DnsLabels;

    #[test]
    fn test_encode_labels() {
        let l = DnsLabels(vec!["google".to_string(), "com".to_string()]);
        println!("{:?}", l.to_bytes())
    }
}