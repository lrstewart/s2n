use std::net::TcpStream;
use std::env;
use std::error::Error;
use replay::replay;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let pcap_file = &args[1];
    let destination = &args[2];
    
    let mut stream = TcpStream::connect(destination).expect(
        "Unable to connect to destination"
    );
    
    replay(&pcap_file, &mut stream)
}
