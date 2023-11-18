pub mod ca;

use crate::ca::{CaError};
use clap::{ArgMatches};
use openssl::error::ErrorStack;
use openssl::x509::{X509Name, X509NameBuilder};
use std::io::Write;
use std::fs;

pub fn append_file(fname: &str, bytes: &Vec<u8>) -> Result<(), CaError> {
    let mut data_file = match fs::OpenOptions::new().create(true).append(true).open(fname) {
        Ok(f) => f,
        Err(err) => return Err(CaError::new(format!("Unable to append to file {}: {}", fname, err.to_string()))),
    };
    match data_file.write_all(bytes.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) => return Err(CaError::new(format!("Unable to append to file {}: {}", fname, err.to_string()))),
    }
}

pub fn read_file(fname: &str) -> Result<Vec<u8>, CaError> {
    match fs::read(fname) {
        Ok(data) => Ok(data),
        Err(err) => return Err(CaError::new(format!("Unable to write file {}: {}", fname, err.to_string()))),
    }
}

pub fn write_file(fname: &str, bytes: &Vec<u8>) -> Result<(), CaError> {
    let mut data_file = match fs::File::create(fname) {
        Ok(f) => f,
        Err(err) => return Err(CaError::new(format!("Unable to write file {}: {}", fname, err.to_string()))),
    };
    match data_file.write_all(bytes.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) => return Err(CaError::new(format!("Unable to write file {}: {}", fname, err.to_string()))),
    }
}

pub fn add_arg_to_name(x509_builder: &mut X509NameBuilder, args: &ArgMatches, arg_name: &str, x509_name: &str) -> Result<(), ErrorStack> {
    let arg : Option<&String> = args.get_one(arg_name);
    if arg.is_some() {
        let value = arg.unwrap();
        if value.len() != 0 {
            x509_builder.append_entry_by_text(x509_name, value)?;
        }
    }
    Ok(())
}

pub fn name_from_args(args: &ArgMatches) -> Result<X509Name, ErrorStack> {
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
pub fn is_all_digits(string: &str) -> bool {
    string.chars().all(|c| c.is_digit(10))
}

// Pad the start time argument if the hours/minutes/seconds have been truncated.
pub fn start_time_from_arg(text: &str) -> Result<String, String> {
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


