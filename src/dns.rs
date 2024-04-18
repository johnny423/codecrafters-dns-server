use std::io::{Result as IOResult, Write};

use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take as take_bytes;
use nom::combinator::map_res;
use nom::error::Error;
use nom::multi::count;
use nom::number::complete::be_u32;
use nom::sequence::tuple;
use nom::Err as NomErr;
use nom::{
    number::complete::{be_u16, be_u8},
    IResult, InputTake,
};

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Writeable {
    fn write(&self, writer: impl Write) -> IOResult<usize>;
}

impl<T: ToBytes> Writeable for T {
    fn write(&self, mut writer: impl Write) -> IOResult<usize> {
        writer.write(self.to_bytes().as_slice())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsAnswer {
    name: DnsLabels,
    answer_type: u16,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

impl ToBytes for DnsAnswer {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.name.to_bytes());
        bytes.extend(&self.answer_type.to_be_bytes());
        bytes.extend(&self.class.to_be_bytes());
        bytes.extend(&self.ttl.to_be_bytes());
        bytes.extend((self.data.len() as u16).to_be_bytes());
        for v in &self.data {
            bytes.extend(v.to_be_bytes());
        }

        bytes
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsLabels(Vec<String>);

impl ToBytes for DnsLabels {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in self.0.iter() {
            bytes.extend((label.len() as u8).to_be_bytes());
            bytes.extend(label.as_bytes());
        }
        bytes.extend(0_u8.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsQuestion {
    qname: DnsLabels,
    qtype: u16,
    qclass: u16,
}

impl ToBytes for DnsQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(&self.qname.to_bytes());
        bytes.extend(&self.qtype.to_be_bytes());
        bytes.extend(&self.qclass.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsHeader {
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

impl ToBytes for DnsHeader {
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsMessage {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsAnswer>,
}

impl ToBytes for DnsMessage {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.header.to_bytes());
        for question in &self.questions {
            bytes.extend(question.to_bytes());
        }
        for answer in &self.answers {
            bytes.extend(answer.to_bytes());
        }

        bytes
    }
}

pub fn response(req: &DnsMessage) -> DnsMessage {
    DnsMessage {
        header: DnsHeader {
            id: req.header.id,
            qr: 1,
            opcode: req.header.opcode,
            aa: 0,
            tc: 0,
            rd: req.header.rd,
            ra: 0,
            z: 0,
            rcode: if req.header.opcode == 0 { 0 } else { 4 },
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        },
        questions: vec![DnsQuestion {
            qname: DnsLabels(vec!["codecrafters".to_string(), "io".to_string()]),
            qtype: 1,
            qclass: 1,
        }],
        answers: vec![DnsAnswer {
            name: DnsLabels(vec!["codecrafters".to_string(), "io".to_string()]),
            answer_type: 1,
            class: 1,
            ttl: 60,
            data: vec![8, 8, 8, 8],
        }],
    }
}

/// Parse
pub fn dns_header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
    let (input, id) = be_u16(input)?;

    let (input, (qr, opcode, aa, tc, rd, ra, z, rcode)) = match dns_header_bits(input) {
        Ok((input, vals)) => Ok((input.0, vals)),
        Err(NomErr::Error(e)) => Err(NomErr::Error(Error::new(e.input.0, e.code))),
        Err(NomErr::Failure(e)) => Err(NomErr::Failure(Error::new(e.input.0, e.code))),
        Err(NomErr::Incomplete(n)) => Err(NomErr::Incomplete(n)),
    }?;
    let (input, (qdcount, ancount, nscount, arcount)) =
        tuple((be_u16, be_u16, be_u16, be_u16))(input)?;
    let header = DnsHeader {
        id,
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        z,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    };

    Ok((input, header))
}

fn dns_header_bits(input: &[u8]) -> IResult<(&[u8], usize), (u8, u8, u8, u8, u8, u8, u8, u8)> {
    let (input, qr) = take_bits(1usize)((input, 0))?;
    let (input, opcode) = take_bits(4usize)(input)?;
    let (input, aa) = take_bits(1usize)(input)?;
    let (input, tc) = take_bits(1usize)(input)?;
    let (input, rd) = take_bits(1usize)(input)?;
    let (input, ra) = take_bits(1usize)(input)?;
    let (input, z) = take_bits(3usize)(input)?;
    let (input, rcode) = take_bits(4usize)(input)?;
    Ok((input, (qr, opcode, aa, tc, rd, ra, z, rcode)))
}

pub fn dns_msg(input: &[u8]) -> IResult<&[u8], DnsMessage> {
    let (input, header) = dns_header(input)?;
    let (input, questions) = count(dns_question, header.qdcount as usize)(input)?;
    let (input, answers) = count(dns_answer, header.ancount as usize)(input)?;

    Ok((
        input,
        DnsMessage {
            header,
            questions,
            answers,
        },
    ))
}

fn dns_answer(input: &[u8]) -> IResult<&[u8], DnsAnswer> {
    let (input, name) = dns_labels(input)?;
    let (input, (answer_type, class, ttl)) = tuple((be_u16, be_u16, be_u32))(input)?;
    let (input, length) = be_u16(input)?;
    let (input, data) = take_bytes(length as usize)(input)?;
    Ok((
        input,
        DnsAnswer {
            name,
            answer_type,
            class,
            ttl,
            data: data.to_vec(),
        },
    ))
}

fn dns_question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
    let (input, qname) = dns_labels(input)?;
    let (input, (qtype, qclass)) = tuple((be_u16, be_u16))(input)?;
    Ok((
        input,
        DnsQuestion {
            qname,
            qtype,
            qclass,
        },
    ))
}

fn dns_labels(input: &[u8]) -> IResult<&[u8], DnsLabels> {
    let mut qname = Vec::new();
    let mut remaining_input = input;
    loop {
        let (input, label) = parse_domain_label(remaining_input)?;
        match label {
            Some(label) => {
                qname.push(label);
                remaining_input = input;
            }
            None => {
                return Ok((input, DnsLabels(qname)));
            }
        }
    }
}

fn parse_domain_label(input: &[u8]) -> IResult<&[u8], Option<String>> {
    let (input, length) = be_u8(input)?;
    if length == 0 {
        // Reached the end of domain name
        return Ok((input, None));
    }
    let (input, label) = map_res(take_bytes(length as usize), |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec())
    })(input)?;
    Ok((input, Some(label)))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_labels() {
        let l = DnsLabels(vec!["google".to_string(), "com".to_string()]);
        println!("{:?}", l.to_bytes())
    }

    #[test]
    fn test_round_trip() {
        let original = DnsMessage {
            header: DnsHeader {
                id: 1234,
                qr: 1,
                opcode: 0,
                aa: 0,
                tc: 0,
                rd: 0,
                ra: 0,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 1,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                qname: DnsLabels(vec!["google".to_string(), "com".to_string()]),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![DnsAnswer {
                name: DnsLabels(vec!["google".to_string(), "com".to_string()]),
                answer_type: 0,
                class: 0,
                ttl: 0,
                data: vec![],
            }],
        };

        let binding = original.to_bytes();
        let results = dns_msg(binding.as_slice());
        assert_eq!(results, Ok((vec![].as_slice(), original)));
    }
}
