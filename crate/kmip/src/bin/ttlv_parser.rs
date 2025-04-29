use std::io::{stdin, stdout, Write};

use cosmian_kmip::{
    kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
    ttlv::{from_ttlv, TTLV},
};

/// A simple command-line parser for TTLV messages.
/// It reads hex strings from the user, decodes them, and parses them into TTLV objects.
/// It also attempts to convert the TTLV objects into KMIP request or response messages.
/// The parser continues until the user types "quit" or "exit".
fn main() {
    println!("TTLV Parser - Enter hex strings (or 'quit' to exit)");
    loop {
        print!("> ");
        stdout().flush().unwrap();

        let mut input = String::new();
        if stdin().read_line(&mut input).is_err() {
            println!("Error reading input");
            continue;
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        if input == "quit" || input == "exit" {
            break;
        }

        match hex::decode(input) {
            Ok(bytes) => match TTLV::from_bytes(&bytes, cosmian_kmip::ttlv::KmipFlavor::Kmip1) {
                Ok(ttlv) => {
                    println!("{ttlv:#?}");
                    if input.starts_with("420078") {
                        let Ok(request) = from_ttlv::<RequestMessage>(ttlv) else {
                            println!("Error converting TTLV to RequestMessage");
                            continue;
                        };
                        println!("{request:#?}");
                    } else if input.starts_with("42007b") || input.starts_with("42007B") {
                        let Ok(response) = from_ttlv::<ResponseMessage>(ttlv) else {
                            println!("Error converting TTLV to ResponseMessage");
                            continue;
                        };
                        println!("{response:#?}");
                    } else {
                        println!("Unknown message type");
                    }
                }
                Err(e) => println!("Error parsing TTLV: {e}"),
            },
            Err(e) => {
                println!("Error parsing hex string: {e}");
            }
        }
    }
}
