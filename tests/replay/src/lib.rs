use std::io::Write;
use rtshark::Metadata;
use std::error::Error;

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

fn sender(packet: &rtshark::Packet) -> &str {
    let mut client = metadata(packet, "tcp.srcport", Metadata::value);
    let server = metadata(packet, "tcp.dstport", Metadata::value);
    if client == server {
        client = metadata(packet, "ip.src", Metadata::value);
    }
    client.expect("Unknown sender")
}

pub fn replay<S: Write>(pcap_file: &str, stream: &mut S) -> Result<(), Box<dyn Error>> {
    // An odd note: running tshark, even just to read a pcap, can lead to strange
    // failed TCP connections with locahost:5037. These will show up in any
    // packet captures taken while this tool is running.
    // This issue is discussed here: https://github.com/gcla/termshark/issues/98
    let mut tshark = rtshark::RTSharkBuilder::builder()
        .input_path(pcap_file)
        .spawn()?;
    
    let mut client: Option<String> = None;
    while let Ok(Some(packet)) = tshark.read() {
        
        // The client is the sender of the first packet.
        let packet_sender = sender(&packet);
        let client_sender = match client {
            Some(ref sender) => sender.as_str(),
            None => {
                println!("Client: {}", packet_sender);
                client = Some(packet_sender.to_string());
                packet_sender
            }
        };
        
        // Send any client TCP data.
        if let Some(payload) = metadata(&packet, "tcp.payload", Metadata::value) {
            // We stop the replay once we encounter server data.
            if client_sender != packet_sender {
                println!("Done");
                break;
            }
            
            let hex_str = payload.replace(":", "");
            let bytes = hex::decode(&hex_str).expect("Unable to parse hex payload");
            stream.write_all(&bytes).expect("Failed to write tcp payload");
            
            let description = metadata(&packet, "tls.record", Metadata::display)
                .unwrap_or("unknown payload");
            println!("Wrote {} bytes: {}", bytes.len(), description);
            if let Some(ja3) = metadata(&packet, "tls.handshake.ja3", Metadata::value) {
                println!("- JA3: {}", ja3);
            }
            if let Some(ja4) = metadata(&packet, "tls.handshake.ja4", Metadata::value) {
                println!("- JA4: {}", ja4);
            }
        }
    }
    Ok(())
}