//! A program that acts as a certificate authority.
//!
//! It
//!   1) Generates root certs.
//!   2) Signs requests with a CA certificate to create child certificate.
//!
//! Note child can be a end entity certificate, for example for a web
//! server. *Or* it can be an intermediate certificate use to sign requests.
//!
//! So the certificate used to sign a request can be the root certificate,
//! or an intermediate certificate created with a provious request.

/// Certificate module.
#[path = "../ca.rs"]
pub mod ca;

/// Application module.
#[path = "../app.rs"]
pub mod app;

use app::*;
use crate::ca::{mk_ca_cert, sign_request, mk_key_pair, get_subject_cn, get_issuer_cn};
use crate::ca::CaError;
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req};
use std::error::Error;
use std::path::Path;

/// Creates a new root CA certificate and key pair, and stores them in files.
///
/// The file names are based on the certificates common name or CN. The
/// root certificate will be in <cn>.crt, the public key in <cn>.key, and
/// the private key in <cn>-private.key.
/// 
fn run_new(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    
    // Process command line arguments.
    // Note defaults are defined by clap, so we could simply call unwrap() safely, but we
    // supply defaults so its clear what happens.
    let root = String::from("root");
    let name = args.get_one("name").unwrap_or(&root);

    let default_days: u32 = 365;
    let days = args.get_one("days").unwrap_or(&default_days).clone();
    
    // Set the start time, using the supplied value if one, otherwise using now.
    let default_start =  Utc::now().format("%Y%m%d%H%M%S").to_string();
    let start = start_time_from_arg(args.get_one::<String>("start").unwrap_or(&default_start))?;

    // Create the root certificate.
    let ca_key_pair = mk_key_pair(2048)?;
    let x509_name = name_from_args(&args)?;
    let ca_cert = mk_ca_cert(&ca_key_pair, &x509_name, &start, days)?;
        
    // Write the CA certificate, public key, and private key to files.
    write_file(&format!("{}.crt", name), ca_cert.to_pem()?.as_ref())?;
    write_file(&format!("{}.key", name), ca_key_pair.public_key_to_pem()?.as_ref())?;
    write_file(&format!("{}-private.key", name), ca_key_pair.private_key_to_pem_pkcs8()?.as_ref())?;
    
    Ok(())
}

/// Save the certificate chain to file starting with the created
/// cert and working our way up the chain.
///
/// The chain terminates when any of the conditions are met:
/// * The issuer CN is the same as the cert's CN.
/// * The issuer's cert file does not exist.
/// * The issuer's CN is blank
///
/// The later exist as a more graceful way for get_issuer_cn() to
/// terminate other than returning Err.
///
/// We are writing to a file with the certs CN value + ".crt".
/// We assume the issuers cert is in a file with the issuer's CN + ".crt"
/// and in the current working directory.
///
/// Normally we write the chain right after signing so we should have
/// access to the immediate parent, but we may not have access to the
/// full chain.
fn write_cert_chain(cert: &X509) -> Result<(), CaError> {

    let mut current_cn = get_subject_cn(&cert)?;
    let mut issuer_cn = get_issuer_cn(&cert)?;


    let certchain = format!("{}.crt", current_cn);
    write_file(&certchain, cert.to_pem()?.as_ref())?;

    while issuer_cn.ne(&current_cn) && issuer_cn.ne("") {
        let issuer_fname = format!("{issuer_cn}.crt");
        if Path::new(&issuer_fname).exists() {
            let issuerbytes = read_file(&issuer_fname)?;
            let issuercert = X509::from_pem(&issuerbytes)?;
            append_file(&certchain, issuercert.to_pem()?.as_ref())?;

            current_cn = issuer_cn.clone();
            issuer_cn = get_issuer_cn(&issuercert)?;
        }
        else {
            // Terminate loop early by making the CN's the same.
            // @TODO log a warning that the chain is incomplete.
            issuer_cn = current_cn.clone();
        };
    }
    Ok(())
}

/// Sign a CSR with the indicated CA.
/// Reads the CSR and CA data from files.
/// Saves the new certificate to a file.
fn run_sign(args: &ArgMatches) -> Result<(), Box<dyn Error>> {

    // Process command line arguments.
    // Note defaults are defined by clap, so we could simply call unwrap() safely, but we
    // supply defaults so its clear what happens.
    let root = String::from("root");
    let ca = args.get_one("ca").unwrap_or(&root);

    let client = String::from("client");
    let csrname = args.get_one("name").unwrap_or(&client);

    let default_days  : u32 = 365;
    let days = args.get_one("days").unwrap_or(&default_days).clone();

    let default_start =  Utc::now().format("%Y%m%d%H%M%S").to_string();
    let start = start_time_from_arg(args.get_one::<String>("start").unwrap_or(&default_start))?;

    // Read CA cert, keys, and CSR from files.
    let cabytes = read_file(&format!("{ca}.crt"))?;
    let cacert = X509::from_pem(&cabytes)?;

    let keybytes = read_file(&format!("{}-private.key", ca))?;
    let private_key = PKey::private_key_from_pem(&keybytes)?;

    let csrbytes = read_file(&format!("{}.csr", csrname))?;
    let csr = X509Req::from_pem(&csrbytes)?;

    // Create the cert and save to file.
    let cert = sign_request(&cacert, &private_key, &csr, &start, days)?;
    write_cert_chain(&cert)?;

    Ok(())
}

/// Dispach the correct function to execute the indicated command.
fn run(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    match args.subcommand() {
        Some(("new", subargs)) => run_new(subargs)?,
        Some(("sign", subargs)) => run_sign(subargs)?,

        Some((cmd, _subargs)) => return Err(Box::try_from(CaError::new(format!("Unknown command: {cmd}")))?),
        _ => return Err(Box::try_from(CaError::new("No command specified".to_string()))?),
    };
    
    Ok(())
}

/// Main
///
/// Set up command line argument definitions then process them.
fn main() -> Result<(), Box<dyn Error>> {
    let args = Command::new("chibica")
        .version("0.0.1")
        .about("Chibi CA")
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
                .value_parser(["2048","3072", "4096", "7680"])
                .help("The number of bits to use when generating the private key")
                .default_value("2048"))
            .arg(Arg::new("start")
                .long("start")
                .help("The UTC start date of the certificate in YYYYMMDD[HH[MM[SS]]] format"))
            .arg(Arg::new("days")
                .long("days")
                .short('d')
                .value_parser(clap::value_parser!(u32))
                .help("The number of days the certificate should be valid")
                .default_value("365")))
        .subcommand(Command::new("sign")
            .about("Sign a CSR")
            .arg(Arg::new("ca")
                .long("ca")
                .short('c')
                .help("The CA to use to sign the certificate, use 'list' to see the available CAs")
                .default_value("root"))
            .arg(Arg::new("name")
                .long("name")
                .short('n')
                .help("The name of the certificate signing request to sign")
                .required(true))
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

