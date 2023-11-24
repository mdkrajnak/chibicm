
//! A crate that implements the major CA functionality.
use std::error::Error;
use std::fmt;
use std::net::{AddrParseError, IpAddr};
use chrono::{Duration, NaiveDateTime};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::{X509, X509Extension, X509Name, X509NameRef, X509Ref, X509Req, X509ReqBuilder, X509v3Context};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use regex::Regex;

#[derive(Debug)]
pub struct CaError {
    details: String
}

impl CaError {
    pub fn new(msg: String) -> CaError {
        CaError{details: msg.to_string()}
    }
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for CaError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl From<ErrorStack> for CaError {
    fn from(err: ErrorStack) -> Self {
        CaError::new(err.to_string())
    }
}

/// Get the common name from a X509Name.
fn get_name_cn(name : &X509NameRef) -> Result<String, CaError> {
    let cn_entry = name
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or(CaError::new("Unable to get certificate common name.".to_string()))?;
    Ok(cn_entry.data().as_utf8()?.to_string())
}

/// Get the common name assocatiate with a certficates issuer.
pub fn get_issuer_cn(cert: &X509) -> Result<String, CaError> {
    get_name_cn(cert.issuer_name())
}

/// Get the common name assocatiate with a certficates subject.
pub fn get_subject_cn(cert: &X509) -> Result<String, CaError> {
    get_name_cn(cert.subject_name())
}


/// Make a certificate and private key signed by the given CA cert and private key
pub fn mk_key_pair(bits: u32) -> Result<PKey<Private>, CaError> {
    let rsa = Rsa::generate(bits)?;
    Ok(PKey::from_rsa(rsa)?)
}

fn days_from_start(start: &str, days: &u32) -> Result<String, CaError> {
    let time_format = "%Y%m%d%H%M%S";
    let parsed = NaiveDateTime::parse_from_str(start, time_format);

    let time = match parsed {
        Ok(value) => value,
        _ => return Err(CaError::new(format!("Unable to format time {start}"))),
    };

    let end = time + Duration::days(i64::from(*days));
    Ok(end.format(time_format).to_string())
}

pub fn mk_ca_cert(key_pair: &PKey<Private>, x509_name: &X509Name, start: &String, days: u32) -> Result<X509, CaError> {

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(x509_name)?;
    cert_builder.set_issuer_name(x509_name)?;
    cert_builder.set_pubkey(key_pair)?;

    let startz = format!("{start}Z");
    let not_before = Asn1Time::from_str(&startz)?;
    cert_builder.set_not_before(&not_before)?;

    let end = days_from_start(start, &days)?;
    let endz = format!("{end}Z");
    let not_after = Asn1Time::from_str(&endz)?;
    cert_builder.set_not_after(&not_after)?;

    // Use for CA certs.
    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    // Refer to RFC 5280 // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

fn is_ip_addr(address: &str) -> bool {
    let test_ip : Result<IpAddr, AddrParseError> = address.parse();
    test_ip.is_ok()
}

fn is_email(email: &str) -> bool {
    //let email_regex = match Regex::new(r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})") {
    let email_regex = match Regex::new(r"^[a-zA-Z0-9_+][a-zA-Z0-9_+\.]*@[a-zA-Z0-9_+\.]+") {
        Ok(matcher) => matcher,
        Err(_) => return false,
    };
    email_regex.is_match(email)
}

fn mk_san_extension(sans: &[&String], context: &X509v3Context) -> Result<X509Extension, CaError> {
    let mut subject_alt_name = SubjectAlternativeName::new();
    for san in sans.iter() {
        if is_ip_addr(san) {
            subject_alt_name.ip(san);
        } else if is_email(san) {
            subject_alt_name.email(san);
        } else {
            subject_alt_name.dns(san);
        }
    }
    Ok(subject_alt_name.build(context)?)
}

/// Make a X509 request with the given private key
pub fn mk_request(key_pair: &PKey<Private>, x509_name: &X509Name, sans: &Vec<&String>, is_ca: bool) -> Result<X509Req, CaError> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;
    req_builder.set_subject_name(x509_name)?;

    let mut extensions : Stack<X509Extension> = Stack::new()?;

    // Add SANs if the SAN vector is not empty.
    if !sans.is_empty() {
        extensions.push(mk_san_extension(sans, &req_builder.x509v3_context(None))?)?;
    }

    // Set basic constrains depending on whether or not we are requesting a
    // intermediate cert to sign endpoint certificates.
    if is_ca {
        let ca_ext = BasicConstraints::new().critical().ca().build()?;
        extensions.push(ca_ext)?;
        extensions.push(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
    }
    else {
        let client_ext = BasicConstraints::new().build()?;
        extensions.push(client_ext)?;
        extensions.push(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .key_encipherment()
                .digital_signature()
                .build()?,
        )?;
    }

    req_builder.add_extensions(&extensions)?;

    req_builder.sign(key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

/// Make a certificate from a request using the given CA and private key
pub fn sign_request(ca_cert: &X509Ref, ca_key_pair: &PKeyRef<Private>, req: &X509Req, start: &str, days: u32) -> Result<X509, CaError> {
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;

    // Assign a random serial number.
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    let pub_key = req.public_key()?;
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&pub_key)?;

    let startz = format!("{start}Z");
    let not_before = Asn1Time::from_str(&startz)?;
    cert_builder.set_not_before(&not_before)?;

    let end = days_from_start(start, &days)?;
    let endz = format!("{end}Z");
    let not_after = Asn1Time::from_str(&endz)?;
    cert_builder.set_not_after(&not_after)?;

    // SKID is the hash of the public key of this certificate.
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    // AKID is the hash of the issuing certificate.
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    // Append the extensions from the CSR.
    let exts = req.extensions()?;
    for ext in exts.iter() {
        cert_builder.append_extension2(ext)?;
    }

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

pub fn mk_self_signed_cert(key_pair: &PKey<Private>, x509_name: &X509Name, sans: &Vec<&String>, start: &String, days: u32) -> Result<X509, CaError> {

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(x509_name)?;
    cert_builder.set_issuer_name(x509_name)?;
    cert_builder.set_pubkey(key_pair)?;

    let startz = format!("{start}Z");
    let not_before = Asn1Time::from_str(&startz)?;
    cert_builder.set_not_before(&not_before)?;

    let end = days_from_start(start, &days)?;
    let endz = format!("{end}Z");
    let not_after = Asn1Time::from_str(&endz)?;
    cert_builder.set_not_after(&not_after)?;

    // Use for CA certs.
    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .key_encipherment()
            .digital_signature()
            .build()?,
    )?;
    // Add SANs if the SAN vector is not empty.
    if !sans.is_empty() {
        cert_builder.append_extension(mk_san_extension(sans, &cert_builder.x509v3_context(None, None))?)?;
    }

    // Refer to RFC 5280 // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use openssl::x509::{X509NameBuilder};

    #[test]
    fn test_days_from_start() -> Result<(), Box<dyn Error>> {
        let start = String::from("20220102010203");
        let days : u32 = 10;
        let expected = String::from("20220112010203");

        let result = days_from_start(&start, &days)?;
        println!("result {result:?}");
        assert_eq!(expected, result);

        Ok(())
    }

    #[test]
    fn test_mk_key_pair() -> Result<(), Box<dyn Error>> {

        // Try 2048 bits.
        let key_pair1 = mk_key_pair(2048)?;
        assert_eq!(2048, key_pair1.bits());

        // Try 512 bits
        let key_pair1 = mk_key_pair(512)?;
        assert_eq!(512, key_pair1.bits());

        Ok(())
    }

    #[test]
    fn test_mk_ca_cert() -> Result<(), Box<dyn Error>> {

        let key_pair = mk_key_pair(2048)?;
        let subject = "ca-common-name";

        let mut x509_builder = X509NameBuilder::new()?;
        x509_builder.append_entry_by_text("CN", subject.clone())?;
        let x509_name = x509_builder.build();

        // Set the start to Jan 2, 2022.
        let start = "20220102000000".to_string();
        let days : u32 = 1;
        let ca_cert = mk_ca_cert(&key_pair, &x509_name, &start, days)?;

        let expected_start = "Jan  2 00:00:00 2022 GMT";
        let expected_end = "Jan  3 00:00:00 2022 GMT";

        assert_eq!(expected_start, ca_cert.not_before().to_string());
        assert_eq!(expected_end, ca_cert.not_after().to_string());

        // For a root cert subject and issuer should be the same.
        assert_eq!(get_subject_cn(&ca_cert)?, get_issuer_cn(&ca_cert)?);
        Ok(())
    }

    #[test]
    fn test_mk_request() -> Result<(), Box<dyn Error>> {
        let key_pair = mk_key_pair(2048)?;
        let subject = "cert-common-name";

        let mut x509_builder = X509NameBuilder::new()?;
        x509_builder.append_entry_by_text("CN", subject.clone())?;
        let x509_name = x509_builder.build();
        let san1 = "localhost".to_string();
        let san2 = "127.0.0.1".to_string();
        let san3 = "::1".to_string();
        let san4 = "local@host.com".to_string();
        let sans : Vec<&String> = vec![&san1, &san2, &san3, &san4];
        let req = mk_request(&key_pair, &x509_name, &sans , false)?;

        assert_eq!(subject, get_name_cn(&req.subject_name())?);

        Ok(())
    }

    #[test]
    fn test_sign_request() -> Result<(), Box<dyn Error>> {
        // Make CA cert.
        let ca_key_pair = mk_key_pair(2048)?;
        let ca_subject = "ca-common-name";

        let mut x509_builder = X509NameBuilder::new()?;
        x509_builder.append_entry_by_text("CN", ca_subject.clone())?;
        let x509_name = x509_builder.build();

        // Set the start to Jan 2, 2022.
        let start = "20220102000000".to_string();
        let days : u32 = 1;
        let ca_cert = mk_ca_cert(&ca_key_pair, &x509_name, &start, days)?;

        // Make CSR
        let key_pair = mk_key_pair(2048)?;
        let subject = "cert-common-name";

        let mut x509_builder = X509NameBuilder::new()?;
        x509_builder.append_entry_by_text("CN", subject.clone())?;
        let x509_name = x509_builder.build();
        let san1 = "localhost".to_string();
        let san2 = "127.0.0.1".to_string();
        let san3 = "::1".to_string();
        let san4 = "local@host.com".to_string();
        let sans : Vec<&String> = vec![&san1, &san2, &san3, &san4];
        let req = mk_request(&key_pair, &x509_name, &sans , false)?;

        let signed = sign_request(&ca_cert, &ca_key_pair, &req, &start, days)?;

        // Check cert.

        // Start and end.
        let expected_start = "Jan  2 00:00:00 2022 GMT";
        let expected_end = "Jan  3 00:00:00 2022 GMT";

        assert_eq!(expected_start, signed.not_before().to_string());
        assert_eq!(expected_end, signed.not_after().to_string());

        // Subject and issuer.
        assert_eq!(subject, get_subject_cn(&signed)?);
        assert_eq!(ca_subject, get_issuer_cn(&signed)?);

        // And there should be 4 SANs.
        let subject_alt_names = signed.subject_alt_names().unwrap();
        assert_eq!(4, subject_alt_names.iter().len());

        Ok(())
    }

    #[test]
    fn test_mk_self_signed_cert() -> Result<(), Box<dyn Error>> {

        let key_pair = mk_key_pair(2048)?;
        let subject = "cert-common-name";

        let mut x509_builder = X509NameBuilder::new()?;
        x509_builder.append_entry_by_text("CN", subject.clone())?;
        let x509_name = x509_builder.build();

        // Set the start to Jan 2, 2022.
        let start = "20220102000000".to_string();
        let days : u32 = 1;

        let san1 = "localhost".to_string();
        let san2 = "127.0.0.1".to_string();
        let san3 = "::1".to_string();
        let san4 = "local@host".to_string();
        let sans : Vec<&String> = vec![&san1, &san2, &san3, &san4];

        let cert = mk_self_signed_cert(&key_pair, &x509_name, &sans, &start, days)?;

        // Check cert

        // Start and end.
        let expected_start = "Jan  2 00:00:00 2022 GMT";
        let expected_end = "Jan  3 00:00:00 2022 GMT";
        assert_eq!(expected_start, cert.not_before().to_string());
        assert_eq!(expected_end, cert.not_after().to_string());

        // The name should match what we specified.
        assert_eq!(subject, get_name_cn(&cert.subject_name())?);

        // For a self signed cert subject and issuer should be the same.
        assert_eq!(get_subject_cn(&cert)?, get_issuer_cn(&cert)?);

        // And there should be 4 SANs.
        let subject_alt_names = cert.subject_alt_names().unwrap();
        assert_eq!(4, subject_alt_names.iter().len());

        Ok(())
    }
}



