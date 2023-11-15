//! A program that generates ca certs, the associate private key, and signs CSRs
//! generated by certificate requestors.

#[path = "../ca.rs"]
pub mod ca;

#[path = "../app.rs"]
pub mod app;

use app::*;
use ca::{mk_private_key, mk_request};
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use clap::parser::ValuesRef;
use std::error::Error;
use crate::ca::mk_self_signed_cert;

/// A program that generates ca certs, certs verified by the ca, and public
/// and private keys.

/// Create CSR from command line arguments an saves the CSR, public, and private keys to files.
fn run_csr(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    // Use values from command line or defaults.
    let client = String::from("client");
    let name = args.get_one("name").unwrap_or(&client);

    let default_sans : ValuesRef<String> = Default::default();
    let sans : Vec<_> = args.get_many("san").unwrap_or(default_sans).collect();

    let is_ca = args.contains_id("isca");

    let default_bits = String::from("2048");
    let bits: u32 = args.get_one("bits").unwrap_or(&default_bits).to_string().parse()?;

    let x509_name = name_from_args(&args)?;

    // Create a key pair and a CSR.
    let key_pair = mk_private_key(bits)?;
    let csr = mk_request(&key_pair, &x509_name, &sans, is_ca)?;

    // Write the CSR, public key, and private key to files.
    write_file(&format!("{}.csr", name), csr.to_pem()?.as_ref())?;
    write_file(&format!("{}.key", name), key_pair.public_key_to_pem()?.as_ref())?;
    write_file(&format!("{}-private.key", name), key_pair.private_key_to_pem_pkcs8()?.as_ref())?;

    Ok(())
}

/// Sign a CSR with the indicated CA.
/// Reads the CSR and CA data from files.
/// Saves the new certificate to a file.
fn run_self(args: &ArgMatches) -> Result<(), Box<dyn Error>> {

    // Process command line arguments.
    let client = String::from("self");
    let certname = args.get_one("name").unwrap_or(&client);

    let default_sans : ValuesRef<String> = Default::default();
    let sans : Vec<_> = args.get_many("san").unwrap_or(default_sans).collect();

    let default_days  : u32 = 365;
    let days = args.get_one("days").unwrap_or(&default_days).clone();

    let default_start =  Utc::now().format("%Y%m%d%H%M%S").to_string();
    let start = start_time_from_arg(args.get_one::<String>("start").unwrap_or(&default_start))?;

    // Get the x509 name.
    let x509_name = name_from_args(&args)?;

    // Create the cert.
    let key_pair = mk_private_key(2048)?;
    let cert = mk_self_signed_cert(&key_pair, &x509_name, &sans, &start, days)?;

    // Write the certificate, public key, and private key to files.
    write_file(&format!("{}.crt", certname), cert.to_pem()?.as_ref())?;
    write_file(&format!("{}.key", certname), key_pair.public_key_to_pem()?.as_ref())?;
    write_file(&format!("{}-private.key", certname), key_pair.private_key_to_pem_pkcs8()?.as_ref())?;

    Ok(())
}

fn run(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    match args.subcommand() {
        Some(("csr", subargs)) => run_csr(subargs)?,
        Some(("self", subargs)) => run_self(subargs)?,

        // @TODO Modify this to print the unknown command and return an error result.
        _ => println!("Unknown command"),
    };
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Command::new("chibica")
        .version("0.0.1")
        .about("Chibi CA user")
        .subcommand(Command::new("csr")
            .about("Create a CSR")
            .arg(Arg::new("name")
                .long("name")
                .short('n')
                .help("The certificate common name (CN)")
                .required(true))
            .arg(Arg::new("organization")
                .long("organization")
                .short('o')
                .help("The CA certificate organization (O)")
                .default_value(""))
            .arg(Arg::new("unit")
                .long("unit")
                .short('u')
                .help("The CA certificate organizational unit (OU)")
                .default_value(""))
            .arg(Arg::new("country")
                .long("country")
                .short('c')
                .help("The CA certificate country (C)")
                .default_value(""))
            .arg(Arg::new("state")
                .long("state")
                .short('s')
                .help("The CA certificate state (ST)")
                .default_value(""))
            .arg(Arg::new("location")
                .long("location")
                .short('l')
                .help("The location (L) to assign to the CA's certifcate")
                .default_value(""))
            .arg(Arg::new("email")
                .long("email")
                .short('e')
                .help("The email (emailAddress) to assign to the CA's certifcate")
                .default_value(""))
            .arg(Arg::new("san")
                .long("san")
                .num_args(0..)
                .help("List of subject alternate names"))
            .arg(Arg::new("isca")
                .long("isca")
                .num_args(0)
                .help("Generate CSR for an intermediate signing certificate."))
            .arg(Arg::new("bits")
                .long("bits")
                .short('b')
                .help("The number of bits to use when generating the private key")
                .default_value("2096")))
        .subcommand(Command::new("self")
            .about("Create a self signed certificate")
            .arg(Arg::new("name")
                .long("name")
                .short('n')
                .help("The certificate common name (CN)")
                .required(true))
            .arg(Arg::new("organization")
                .long("organization")
                .short('o')
                .help("The CA certificate organization (O)")
                .default_value(""))
            .arg(Arg::new("unit")
                .long("unit")
                .short('u')
                .help("The CA certificate organizational unit (OU)")
                .default_value(""))
            .arg(Arg::new("country")
                .long("country")
                .short('c')
                .help("The CA certificate country (C)")
                .default_value(""))
            .arg(Arg::new("state")
                .long("state")
                .short('s')
                .help("The CA certificate state (ST)")
                .default_value(""))
            .arg(Arg::new("location")
                .long("location")
                .short('l')
                .help("The location (L) to assign to the CA's certifcate")
                .default_value(""))
            .arg(Arg::new("email")
                .long("email")
                .short('e')
                .help("The email (emailAddress) to assign to the CA's certifcate")
                .default_value(""))
            .arg(Arg::new("san")
                .long("san")
                .num_args(0..)
                .help("List of subject alternate names"))
            .arg(Arg::new("bits")
                .long("bits")
                .short('b')
                .help("The number of bits to use when generating the private key")
                .default_value("2096"))
            .arg(Arg::new("start")
                .long("start")
                .help("The UTC start date of the certificate in YYYYMMDD[HH[MM[SS]]] format"))
            .arg(Arg::new("days")
                .long("days")
                .short('d')
                .value_parser(clap::value_parser!(u32))
                .help("The number of days the certificate should be valid")
                .default_value("365")))
        .get_matches();
    
    run(&args)?;
    
    Ok(())
}

