use std::io::{Write, stdin, stdout};

use cosmian_kmip::{
    kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
    ttlv::{KmipFlavor, TTLV, from_ttlv},
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
            Ok(bytes) => {
                let Ok((major, minor)) = TTLV::find_version(&bytes) else {
                    println!("ERROR: Failed to find KMIP version");
                    continue;
                };
                let kmip_flavor = if major == 1 {
                    KmipFlavor::Kmip1
                } else if major == 2 {
                    KmipFlavor::Kmip2
                } else {
                    println!("ERROR: Unsupported KMIP version: {major}.{minor}",);
                    continue;
                };
                match TTLV::from_bytes(&bytes, kmip_flavor) {
                    Ok(ttlv) => {
                        println!("\nTTLV ==> \n\n{ttlv:#?}\n");
                        if input.starts_with("420078") {
                            match from_ttlv::<RequestMessage>(ttlv) {
                                Err(r) => {
                                    println!("ERROR converting TTLV to RequestMessage: {r}");
                                    continue;
                                },
                                Ok(request) => println!("Request ==>\n\n{request:#?}")
                            };
                        } else if input.starts_with("42007b") || input.starts_with("42007B") {
                            match from_ttlv::<ResponseMessage>(ttlv) {
                                Err(r) => {
                                    println!("ERROR converting TTLV to ResponseMessage: {r}");
                                    continue;
                                },
                                Ok(response) => println!("Response ==>\n\n{response:#?}")
                            };
                        } else {
                            println!("ERROR: unknown message type");
                        }
                    }
                    Err(e) => println!("ERROR parsing TTLV: {e}"),
                }
            }
            Err(e) => {
                println!("ERROR parsing hex string: {e}");
            }
        }
    }
}
