use std::env;
use rtshark::Metadata;
use std::collections::HashSet;
use std::error::Error;
use s2n_tls::client_hello::ClientHello as S2NClientHello;
use s2n_tls::fingerprint::FingerprintType;

fn metadata<'a>(
    packet: &'a rtshark::Packet,
    key: &'a str,
    f: fn(&'a Metadata) -> &'a str
) -> Option<&'a str> {
    match key.split_once(".") {
        None => packet.layer_name(key).map(rtshark::Layer::name),
        Some((layer_name, _)) => {
            packet.layer_name(layer_name)
                .and_then(|layer| layer.metadata(key))
                .map(f)
        },
    }
}

const CLIENT_HELLO_FILTER: &str = "tls.handshake.type == 1";
const FRAGMENT: &str = "tls.handshake.fragment";
const FRAGMENTS_COUNT: &str = "tls.handshake.fragment.count";
const JA3: &str = "tls.handshake.ja3";
const JA4: &str = "tls.handshake.ja4";
const PAYLOAD_FILTER: &str = PAYLOAD;
const PAYLOAD: &str = "tcp.payload";
const FRAME_NUM: &str = "frame.number";

struct ClientHello {
    payloads: Vec<String>,
    payload_nums: HashSet<String>,
    ja3: String,
    ja4: String,
}

impl ClientHello {
    fn test(&self) -> Result<(), Box<dyn Error>> {
        let hex = self.payloads.join("");
        let bytes = hex::decode(&hex)?;
        assert!(bytes.len() > 5);
        
        let mut output = Vec::new();
        let s2n_hello = S2NClientHello::parse_client_hello(&bytes[5..])?;
        s2n_hello.fingerprint_hash(FingerprintType::JA3, &mut output)?;
        println!("here");
        println!("{:?} vs {:?}", self.ja3.as_bytes(), output);
        assert!(output == self.ja3.as_bytes());
        Ok(())
    }
    
    fn validate(&self) -> bool {
        if self.payload_nums.is_empty() {
            self.payloads.len() == 1
        } else {
            self.payloads.len() == self.payload_nums.len()
        }
    }
    
    fn accept(&mut self, packet: &rtshark::Packet) -> bool {
        if let Some(num) = metadata(packet, FRAME_NUM, Metadata::value) {
            if !self.payload_nums.contains(num) {
                return false;
            }
            if let Some(payload) = metadata(packet, PAYLOAD, Metadata::value) {
                self.payloads.push(payload.to_string());
                return true;
            }
        }
        return false;
    }
    
    fn from(packet: &rtshark::Packet) -> Option<ClientHello> {
        let ja3 = metadata(packet, JA3, Metadata::value)?.to_string();
        let ja4 = metadata(packet, JA4, Metadata::value)?.to_string();
        
        let mut payloads = Vec::new();
        let mut payload_nums = HashSet::new();
        if let Some(payload) = metadata(packet, PAYLOAD, Metadata::value) {
            payloads.push(payload.to_string());
        } else {
            for metadata in packet.layer_name("tls")?.iter() {
                if metadata.name() == FRAGMENT {
                    payload_nums.insert(metadata.value().to_string());
                }
            }
            let payloads_count = metadata(packet, FRAGMENTS_COUNT, Metadata::value)?;
            if payloads_count == payload_nums.len().to_string() {
                return None;
            }
        }
        
        Some(ClientHello{payloads, payload_nums, ja3, ja4})
    }
}

fn from_capture(file: &str) -> Result<Vec<ClientHello>, Box<dyn Error>> {
    let mut client_hellos = Vec::new();
    
    let mut client_hello_reader = rtshark::RTSharkBuilder::builder()
        .input_path(file)
        .display_filter(CLIENT_HELLO_FILTER)
        .metadata_whitelist(FRAGMENT)
        .metadata_whitelist(FRAGMENTS_COUNT)
        .metadata_whitelist(JA3)
        .metadata_whitelist(JA4)
        .metadata_whitelist(PAYLOAD)
        .metadata_whitelist(FRAME_NUM)
        .spawn()?;
    
    while let Ok(Some(packet)) = client_hello_reader.read() {
        if let Some(client_hello) = ClientHello::from(&packet) {
            client_hellos.push(client_hello);
        }
    }
    
    let mut fragment_reader = rtshark::RTSharkBuilder::builder()
        .input_path(file)
        .display_filter(PAYLOAD_FILTER)
        .metadata_whitelist(PAYLOAD)
        .metadata_whitelist(FRAME_NUM)
        .spawn()?;
    while let Ok(Some(packet)) = fragment_reader.read() {
        for client_hello in client_hellos.iter_mut() {
            if client_hello.accept(&packet) {
                break;
            }
        }
    }
    client_hellos.retain(ClientHello::validate);
    Ok(client_hellos)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    for input in &args[1..] {
        println!("pcap: {}", input);
        let client_hellos = from_capture(input)?;
        for client_hello in client_hellos.iter() {
            println!("client_hello: {} {}",
                client_hello.ja3, client_hello.ja4);
            client_hello.test()?;
        }
    }
    println!("SUCCESS");
    Ok(())
}
