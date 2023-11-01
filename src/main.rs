//! A program that generates ca certs, the associate private key, and signs CSRs
//! generated by certificate requestors.

pub mod ca;

use ca::{mk_private_key, mk_request, mk_ca_signed_cert};
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Name, X509NameBuilder, X509Req};
use std::error::Error;
use std::io::Write;
use std::fs;

/// A program that generates ca certs, certs verified by the ca, and public
/// and private keys.

fn add_arg_to_name(x509_builder: &mut X509NameBuilder, args: &ArgMatches, arg_name: &str, x509_name: &str) -> Result<(), ErrorStack> {
    let arg : Option<&String> = args.get_one(arg_name);
    if arg.is_some() {
        let value = arg.unwrap();
        if value.len() != 0 {
            x509_builder.append_entry_by_text(x509_name, arg.unwrap())?;
        }
    }
    Ok(())
}

fn name_from_args(args: &ArgMatches) -> Result<X509Name, ErrorStack> {
    let mut x509_builder = X509NameBuilder::new()?;

    add_arg_to_name(&mut x509_builder, &args, "name", "CN")?;
    add_arg_to_name(&mut x509_builder, &args, "country", "C")?;
    add_arg_to_name(&mut x509_builder, &args, "state", "ST")?;
    add_arg_to_name(&mut x509_builder, &args, "location", "L")?;
    add_arg_to_name(&mut x509_builder, &args, "organization", "O")?;
    add_arg_to_name(&mut x509_builder, &args, "unit", "OU")?;
    add_arg_to_name(&mut x509_builder, &args, "email", "emailAddress")?;
    
    Ok(x509_builder.build())
}

/// Return true if all of the characters in a string are digits.
fn is_all_digits(string: &str) -> bool {
    string.chars().all(|c| c.is_digit(10))
}

// Pad the start time argument if the hours/minutes/seconds have been truncated.
fn start_time_from_arg(text: &str) -> Result<String, String> {
    if !is_all_digits(&text) {
        return Err(format!("The start time given: {text}, contains characters that are not digits"));
    }
    if text.len() == 8 {
        return Ok(format!("{text}000000"))
    }
    if text.len() == 10 {
        return Ok(format!("{text}0000"))
    }
    if text.len() == 12 {
        return Ok(format!("{text}00"))
    }
    if text.len() == 14 {
        return Ok(format!("{text}"))
    }
    Err(format!("{text} must be in YYYYMMDD, YYYYMMDDHH, YYYYMMDDHHMM, or YYYYMMDDHHMMSS format. Times must be UTC."))
}

/// Creates a new CA certificate and key and stores them in files.
/// 
/// # Returns
/// 
/// Ok: (), Err: An error string.
/// 
fn run_new(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    
    // Process command line arguments.
    let root = String::from("root");
    let name = args.get_one("name").unwrap_or(&root);

    let default_days: u32 = 365;
    let days = args.get_one("days").unwrap_or(&default_days).clone();
    
    // Set the start time, using the supplied value if one, otherwise using now.
    let default_start =  Utc::now().format("%Y%m%d%H%M%S").to_string();
    let start = start_time_from_arg(args.get_one::<String>("start").unwrap_or(&default_start))?;

    let x509_name = name_from_args(&args).unwrap();
    let (ca_cert, ca_key_pair) = ca::mk_ca_cert(&x509_name, &start, days)?;
        
    // Write the CA certificate to a file.
    let mut ca_certificate_file = std::fs::File::create(format!("{}.crt", name))?;
    ca_certificate_file.write_all(ca_cert.to_pem().unwrap().as_ref())?;
    
    // Write the CA private key to a file.
    let mut key_file = std::fs::File::create(format!("{}.key", name))?;
    key_file.write_all(ca_key_pair.private_key_to_pem_pkcs8().unwrap().as_ref())?;
    
    Ok(())
}

/// Create CSR from command line arguments an saves the CSR, public, and private keys to files.
fn run_csr(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    // Use values from command line or defaults.
    let client = String::from("client");
    let name = args.get_one("name").unwrap_or(&client);

    let default_bits: u32 = 2048;
    let bits: u32 = args.get_one("bits").unwrap_or(&default_bits).clone();

    // Construct a X509 name from cli arguments.
    let x509_name = name_from_args(&args)?;

    // Create a key pair and a CSR.
    let key_pair = mk_private_key(bits)?;
    let csr = mk_request(&key_pair, &x509_name)?;

    // Write the client CSR to a file.
    let mut csr_file = std::fs::File::create(format!("{}.csr", name))?;
    csr_file.write_all(csr.to_pem()?.as_ref())?;
    
    // Write the client public key to a file.
    let mut pub_key_file = std::fs::File::create(format!("{}.key", name))?;
    pub_key_file.write_all(key_pair.public_key_to_pem()?.as_ref())?;

    // Write the client private key to a file.
    let mut key_file = std::fs::File::create(format!("{}-private.key", name))?;
    key_file.write_all(key_pair.private_key_to_pem_pkcs8()?.as_ref())?;
    
    Ok(())
}

/// Sign a CSR with the indicated CA.
/// Reads the CSR and CA data from files.
/// Saves the new certificate to a file.
fn run_sign(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    // Process command line arguments.
    let root = String::from("root");
    let ca = args.get_one("ca").unwrap_or(&root);

    let client = String::from("client");
    let csrname = args.get_one("in").unwrap_or(&client);
    let certname = args.get_one("out").unwrap_or(&client);

    // Get start and days from cli args.
    let default_days: u32 = 365;
    let days = args.get_one("days").unwrap_or(&default_days).clone();
    
    // Set the start time, using the supplied value if one, otherwise using now.
    let default_start =  Utc::now().format("%Y%m%d%H%M%S").to_string();
    let start = start_time_from_arg(args.get_one::<String>("start").unwrap_or(&default_start))?;

    // Read CA cert, keys, and CSR from files.
    let cabytes = fs::read(format!("{}.crt", ca))?;
    let cacert = X509::from_pem(&cabytes)?;

    let keybytes = fs::read(format!("{}-private.key", ca))?;
    let private_key = PKey::private_key_from_pem(&keybytes)?;

    let csrbytes = fs::read(format!("{}.csr", csrname))?;
    let csr = X509Req::from_pem(&csrbytes)?;

    // Create the cert.
    let cert = mk_ca_signed_cert(&cacert, &private_key, &csr, &start, days)?;

    // Save to file.
    let mut certificate_file = std::fs::File::create(format!("{}.crt", certname))?;
    certificate_file.write_all(cert.to_pem()?.as_ref())?;

    Ok(())
}

fn run(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    match args.subcommand() {
        Some(("csr", subargs)) => run_csr(subargs)?,
        Some(("new", subargs)) => run_new(subargs)?,
        Some(("sign", subargs)) => run_sign(subargs)?,

        // @TODO Modify this to print the unknown command and return an error result.
        _ => println!("Unknown command"),
    };
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Command::new("chibica")
        .version("0.0.1")
        .about("Chibi CA")
        .subcommand(Command::new("exists")
            .about("Check to see if a CA exists.")
            .arg(Arg::new("ca")
                .long("ca")
                .help("Name of the new root CA")
                .default_value("root")))
        .subcommand(Command::new("new")
            .about("Create a new root CA")
            .arg(Arg::new("name")
                .long("name")
                .short('n')
                .help("The CA certificate common name (CN)")
                .default_value("root"))
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
            .arg(Arg::new("bits")
                .long("bits")
                .short('b')
                .help("The number of bits to use when generating the private key")
                .default_value("2096")))
        .subcommand(Command::new("sign")
            .about("Sign a CSR")
            .arg(Arg::new("ca")
                .long("ca")
                .short('c')
                .help("The CA to use to sign the certificate, use 'list' to see the available CAs")
                .default_value("root"))
            .arg(Arg::new("in")
                .long("in")
                .short('i')
                .help("The CSR file with the request to sign")
                .required(true))
            .arg(Arg::new("out")
                .long("out")
                .short('o')
                .help("The name of the output file for the signed certificate")
                .required(true)))
        .get_matches();
    
    run(&args)?;
    
    Ok(())
}

