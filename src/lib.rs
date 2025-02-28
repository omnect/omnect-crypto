use anyhow::{Context, Result};
use std::sync::Once;
use x509_parser::prelude::FromDer;
use x509_parser::extensions::ParsedExtension;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use log::debug;
use der_parser::oid;

static OPENSSL_INIT_ONCE: Once = Once::new();

#[derive(Clone)]
pub struct Crypto {
    pub ca_key: openssl::pkey::PKey<openssl::pkey::Private>,
    pub ca_cert_stack: Vec<openssl::x509::X509>,
    pub verify_flags: openssl::x509::verify::X509VerifyFlags,
}

impl Crypto {
    pub fn new(ca_key: &[u8], ca_cert: &[u8]) -> Result<Self> {
        OPENSSL_INIT_ONCE.call_once(openssl::init);

        let ca_key = openssl::rsa::Rsa::private_key_from_pem(ca_key)?;
        let ca_key = openssl::pkey::PKey::from_rsa(ca_key)?;
        let ca_cert_stack = openssl::x509::X509::stack_from_pem(ca_cert)?;
        let verify_flags = openssl::x509::verify::X509VerifyFlags::CRL_CHECK_ALL
            | openssl::x509::verify::X509VerifyFlags::POLICY_CHECK
            | openssl::x509::verify::X509VerifyFlags::EXTENDED_CRL_SUPPORT
            | openssl::x509::verify::X509VerifyFlags::USE_DELTAS;

        Ok(Crypto {
            ca_key,
            ca_cert_stack,
            verify_flags,
        })
    }

    pub fn create_cert_and_key(
        &self,
        name: &str,
        days: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = openssl::rsa::Rsa::generate(4096).with_context(|| "Could not generate key.")?;
        let private_key_pem = key.private_key_to_pem()?;

        let pub_key =
            openssl::rsa::Rsa::from_public_components(key.n().to_owned()?, key.e().to_owned()?)?;

        let pkey = openssl::pkey::PKey::from_rsa(pub_key)?;

        let device_cert = self.create_cert(&pkey, name, &None, days)?;
        let device_cert_pem = device_cert.to_pem()?;

        Ok((device_cert_pem, private_key_pem))
    }

    pub fn default_extensions(
        &self,
        cert_builder: &mut openssl::x509::X509Builder,
    ) -> Result<(), anyhow::Error> {
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .pathlen(0)
            .build()?;
        cert_builder.append_extension(basic_constraints)?;
        let eku = openssl::x509::extension::ExtendedKeyUsage::new()
            .critical()
            .client_auth()
            .build()?;
        cert_builder.append_extension(eku)?;
        let ku = openssl::x509::extension::KeyUsage::new()
            .critical()
            .digital_signature()
            .non_repudiation()
            .key_encipherment()
            .build()?;
        cert_builder.append_extension(ku)?;
        Ok(())
    }

    pub fn copy_extensions(
        &self,
        extensions: &openssl::stack::Stack<openssl::x509::X509Extension>,
        cert_builder: &mut openssl::x509::X509Builder,
        ca_cert: &openssl::x509::X509,
    ) -> Result<(), anyhow::Error> {
        for ext in extensions.iter() {
            let ext_der = ext.to_der()?;
            debug!("{:x?}", ext_der);
            let res = x509_parser::extensions::X509Extension::from_der(ext_der.as_ref());
            match res {
                Ok((_rem, ext)) => {
                    debug!("Extension OID: {}", ext.oid);
                    debug!("  Critical: {}", ext.critical);
                    let parsed_ext = ext.parsed_extension();
                    if parsed_ext.unsupported() || parsed_ext.error().is_some() {
                        continue;
                    }
                    match parsed_ext {
                        ParsedExtension::SubjectAlternativeName(san) => {
                            let ext_ctx = cert_builder.x509v3_context(Some(ca_cert), None);
                            let mut san_ext = &mut openssl::x509::extension::SubjectAlternativeName::new();
                            if ext.critical {
                                san_ext = san_ext.critical();
                            }

                            for item  in san.general_names.iter() {
                                match item {
                                    x509_parser::prelude::GeneralName::DNSName(name) => {
                                        san_ext.dns(name);
                                    }
                                    x509_parser::prelude::GeneralName::IPAddress(ip) => {
                                        if ip.len() == 4 { // ipv4
                                            // ip is in network byte order (bit endian)
                                            let mut rdr = Cursor::new(ip);
                                            let addr = rdr.read_u32::<BigEndian>().unwrap();
                                            let ipv4 = std::net::Ipv4Addr::from(addr);
                                            san_ext.ip(&ipv4.to_string());
                                        } else if ip.len() == 16 { // ipv6
                                            // ip is in network byte order (bit endian)
                                            let mut rdr = Cursor::new(ip);
                                            let addr = rdr.read_u128::<BigEndian>().unwrap();
                                            let ipv6 = std::net::Ipv6Addr::from(addr);
                                            san_ext.ip(&ipv6.to_string());
                                        } else {
                                            debug!("invalid IP address encoded {:?}",ip);
                                        }
                                    },
                                    _ => { debug!("SAN type not supported: {:?}",item) }
                                }
                            }
                            let san_ext = san_ext.build(&ext_ctx)?;
                            cert_builder.append_extension(san_ext)?;
                        },
                        ParsedExtension::KeyUsage(ku) => {
                            let mut out = &mut openssl::x509::extension::KeyUsage::new();
                            if ext.critical { out = out.critical(); }
                            if ku.crl_sign() { out = out.crl_sign(); }
                            if ku.data_encipherment() { out = out.data_encipherment(); }
                            if ku.decipher_only() { out = out.decipher_only(); }
                            if ku.digital_signature() { out = out.digital_signature(); }
                            if ku.encipher_only() { out = out.encipher_only(); }
                            if ku.key_agreement() { out = out.key_agreement(); }
                            if ku.key_cert_sign() { out = out.key_cert_sign(); }
                            if ku.key_encipherment() { out = out.key_encipherment(); }
                            if ku.non_repudiation() { out = out.non_repudiation(); }
                            cert_builder.append_extension(out.build()?)?;
                        }
                        ParsedExtension::BasicConstraints(bc) => {
                            let mut out = &mut openssl::x509::extension::BasicConstraints::new();
                            if ext.critical { out = out.critical(); }
                            if bc.ca { out = out.ca().pathlen(0); }
                            // Security constraint - least priviledge:
                            //   Do not copy pathlen from CSR, instead force it to 0 so the cert only can sign leaf certs.
                            // Next line would use pathlen from CSR:
                            //   if bc.path_len_constraint.is_some() { out = out.pathlen(bc.path_len_constraint.unwrap()); }
                            cert_builder.append_extension(out.build()?)?;
                        }
                        ParsedExtension::ExtendedKeyUsage(eku) => {
                            let mut out = &mut openssl::x509::extension::ExtendedKeyUsage::new();
                            if ext.critical { out = out.critical(); }
                            if eku.client_auth { out = out.client_auth(); }
                            if eku.code_signing { out = out.code_signing(); }
                            if eku.email_protection { out = out.email_protection(); }
                            if eku.ocsp_signing {
                                let oid: [u8;8] = oid!(raw 1.3.6.1.5.5.7.3.9);
                                out = out.other(std::str::from_utf8(&oid).unwrap());
                            }
                            if eku.server_auth { out = out.server_auth(); }
                            if eku.time_stamping { out = out.time_stamping(); }
                            if eku.any {
                                let oid: [u8;4] = oid!(raw 2.5.29.37.0);
                                out = out.other(std::str::from_utf8(&oid).unwrap());
                            }
                            cert_builder.append_extension(out.build()?)?;
                        }
                        ParsedExtension::UnsupportedExtension{oid} => {
                            debug!("unsupported extension: {:?}", oid);
                            continue;
                        },
                        ParsedExtension::ParseError{error} => {
                            debug!("error in parsing extension: {:?}", error);
                            continue;
                        }
                        _ => {} // ignore extension
                    }
                },
                _ => {
                    debug!("x509 extension parsing failed: {:?}", res);
                }
            }
        }
        Ok(())
    }

    pub fn create_cert(
        &self,
        pub_key: &openssl::pkey::PKey<openssl::pkey::Public>,
        cn: &str,
        csr: &Option<openssl::x509::X509Req>,
        days: u32,
    ) -> Result<openssl::x509::X509> {
        let serial_number = openssl::bn::BigNum::from_u32(1)?;
        let serial_number_asn = openssl::asn1::Asn1Integer::from_bn(&serial_number)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(days)?;

        let subject_name = match csr {
            Some(csr) => {
                csr.subject_name()
            },
            None => {
                let mut subject_name = openssl::x509::X509NameBuilder::new()?;
                subject_name.append_entry_by_text("C", "DE")?;
                subject_name.append_entry_by_text("ST", "BY")?;
                subject_name.append_entry_by_text("O", "conplement AG")?;
                subject_name.append_entry_by_text("CN", cn)?;
                &subject_name.build()
            }
        };

        let mut cert_builder = openssl::x509::X509Builder::new()?;
        cert_builder.set_version(2)?;
        cert_builder.set_not_before(&not_before)?;
        cert_builder.set_not_after(&not_after)?;
        cert_builder.set_serial_number(&serial_number_asn)?;
        cert_builder.set_subject_name(subject_name)?;
        cert_builder.set_pubkey(pub_key)?;
        let ca_cert = self.ca_cert_stack.first().unwrap(); // safe here
        let issuer = ca_cert.subject_name();
        cert_builder.set_issuer_name(issuer)?;
    
        match csr {
            Some(csr) => {
                // Copy extensions from CSR if present
                match csr.extensions() {
                    Ok(extensions) => {
                        self.copy_extensions(&extensions, &mut cert_builder, ca_cert)?;
                    }
                    Err(err) => {
                        debug!("Could not read extensions from CSR: {:?}", err);
                        self.default_extensions(&mut cert_builder)?;
                    }
                }
            },
            None => {
                self.default_extensions(&mut cert_builder)?;
            },
        }

        let ski = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(ski)?;
        let aki = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&cert_builder.x509v3_context(Some(ca_cert.as_ref()), None))?;
        cert_builder.append_extension(aki)?;
        cert_builder.sign(&self.ca_key, openssl::hash::MessageDigest::sha256())?;
        let created_cert = cert_builder.build();
        self.verify_cert(&created_cert.to_pem()?)?;
        Ok(created_cert)
    }

    pub fn verify_cert(&self, cert: &[u8]) -> Result<(), anyhow::Error> {
        let cert = openssl::x509::X509::from_pem(cert)?;
        let mut truststore_builder = openssl::x509::store::X509StoreBuilder::new()?;
        for i in self.ca_cert_stack.iter() {
            truststore_builder.add_cert(i.clone())?;
        }
        truststore_builder.set_flags(self.verify_flags)?;
        let truststore = truststore_builder.build();
        let mut truststore_context = openssl::x509::X509StoreContext::new()?;
        let empty_cert_chain = openssl::stack::Stack::new()?;

        if !truststore_context.init(&truststore, &cert, &empty_cert_chain, |c| c.verify_cert())? {
            return Err(anyhow::anyhow!(
                "couldn't verify certificate against ca chain, reason: {}",
                truststore_context.error(),
            ));
        }
        Ok(())
    }

    pub fn get_csr_builder_from_key_and_cert(
        client_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        client_cert: &openssl::x509::X509,
    ) -> Result<openssl::x509::X509ReqBuilder> {
        let mut exts = openssl::stack::Stack::new()?;
        exts.push(
            openssl::x509::extension::ExtendedKeyUsage::new()
                .client_auth()
                .build()?,
        )?;
        let mut csr_builder = openssl::x509::X509Req::builder()?;
        csr_builder.set_version(0)?;
        csr_builder.set_subject_name(client_cert.subject_name())?;
        csr_builder.add_extensions(&exts)?;
        csr_builder.set_pubkey(client_key)?;
        csr_builder.sign(client_key, openssl::hash::MessageDigest::sha256())?;

        Ok(csr_builder)
    }

    pub fn create_csr_from_key_and_cert_raw(
        cert_key_pem: &[u8],
        cert_pem: &[u8],
    ) -> Result<Vec<u8>> {
        let client_cert = openssl::x509::X509::from_pem(cert_pem)?;
        let client_key = openssl::rsa::Rsa::private_key_from_pem(cert_key_pem)?;
        let client_key = openssl::pkey::PKey::from_rsa(client_key)?;

        let csr_builder = Self::get_csr_builder_from_key_and_cert(&client_key, &client_cert)?;

        Ok(csr_builder.build().to_pem()?)
    }

    pub fn get_csr_builder(&self) -> Result<openssl::x509::X509ReqBuilder> {
        let key = &self.ca_key;
        let cert = self
            .ca_cert_stack
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty ca cert chain"))?;
        let csr_builder = Self::get_csr_builder_from_key_and_cert(key, cert)?;

        Ok(csr_builder)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use log::debug;

    fn create_cert_from_scatch(key: &openssl::rsa::Rsa<openssl::pkey::Private>) -> Vec<u8> {
        let serial_number = openssl::bn::BigNum::from_u32(1).unwrap();
        let serial_number_asn = openssl::asn1::Asn1Integer::from_bn(&serial_number).unwrap();
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(1).unwrap();

        let mut subject_name = openssl::x509::X509NameBuilder::new().unwrap();
        subject_name
            .append_entry_by_text("CN", "test_ca_cert")
            .unwrap();
        let subject_name = subject_name.build();
        let mut cert_builder = openssl::x509::X509Builder::new().unwrap();
        cert_builder.set_version(2).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();
        cert_builder.set_serial_number(&serial_number_asn).unwrap();
        cert_builder.set_subject_name(&subject_name).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(key.clone()).unwrap();
        cert_builder.set_pubkey(&pkey).unwrap();
        let issuer = subject_name; // self signed certificate
        cert_builder.set_issuer_name(&issuer).unwrap();
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .ca()
            .critical()
            .build()
            .unwrap();
        cert_builder.append_extension(basic_constraints).unwrap();
        let key_usage = openssl::x509::extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()
            .unwrap();
        cert_builder.append_extension(key_usage).unwrap();
        let subject_key_identitfier = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(None, None))
            .unwrap();
        cert_builder
            .append_extension(subject_key_identitfier)
            .unwrap();
        let authority_key_identifier = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&cert_builder.x509v3_context(None, None))
            .unwrap();
        cert_builder
            .append_extension(authority_key_identifier)
            .unwrap();
        cert_builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        cert_builder.build().to_pem().unwrap()
    }

    #[test]
    fn returns_valid_keys_and_certs() -> Result<(), anyhow::Error> {
        let key = openssl::rsa::Rsa::generate(4096)?; // doesnt work in test context: .with_context(|| "Could not generate key.")?;
        let private_key_pem = key.private_key_to_pem()?;
        let ca_cert = create_cert_from_scatch(&key);

        let crypto = super::Crypto::new(&private_key_pem, &ca_cert)?;
        let (device_cert_pem, device_key_pem) =
            crypto.create_cert_and_key("TestDevice", 1)?;

        // keys and certs need to be parseable PEM
        let device_private_key = openssl::rsa::Rsa::private_key_from_pem(&device_key_pem)?;
        assert_eq!(device_private_key.check_key()?, true);

        // key in cert needs to match input parameter
        let device_cert = openssl::x509::X509::from_pem(&device_cert_pem)?;
        assert_eq!(format!("{:?}", device_cert.subject_name()), "[countryName = \"DE\", stateOrProvinceName = \"BY\", organizationName = \"conplement AG\", commonName = \"TestDevice\"]");
        assert_eq!(
            format!("{:?}", device_cert.issuer_name()),
            "[commonName = \"test_ca_cert\"]"
        );
        assert_eq!(
            format!("{:?}", device_cert.signature_algorithm().object()),
            "sha256WithRSAEncryption"
        );
        Ok(())
    }

    #[test]
    fn returns_valid_csr() {
        let key = openssl::rsa::Rsa::generate(4096).unwrap();
        let private_key_pem = key.private_key_to_pem().unwrap();
        let cert_pem = create_cert_from_scatch(&key);
        let crypto = super::Crypto::new(&private_key_pem, &cert_pem).unwrap();
        let csr =
            super::Crypto::create_csr_from_key_and_cert_raw(&private_key_pem, &cert_pem).unwrap();
        let cert = crypto.ca_cert_stack.first().unwrap();
        let csr = openssl::x509::X509Req::from_pem(&csr).unwrap();
        let csr_subject = csr.subject_name().to_der().unwrap();
        let cert_subject = cert.subject_name().to_der().unwrap();

        assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
        assert!(csr.verify(cert.public_key().unwrap().as_ref()).unwrap());
        assert_eq!(csr_subject, cert_subject);
    }

    #[test]
    fn can_sign_intermediate_from_csr() {
        env_logger::init();
        let rootca_key_str = std::fs::read_to_string("test-data/root-ca.key").unwrap();
        let rootca_cert_str = std::fs::read_to_string("test-data/root-ca.crt").unwrap();
        let crypto = crate::Crypto::new(rootca_key_str.as_bytes(), rootca_cert_str.as_bytes()).unwrap();

        let intermediate_csr_str = std::fs::read_to_string("test-data/intermediate-ca.csr").unwrap();
        let pkcs10 = openssl::x509::X509Req::from_pem(intermediate_csr_str.as_bytes())
            .with_context(|| "couldn't read in certificate sign request as pem").unwrap();

        let pub_key = pkcs10
            .public_key()
            .with_context(|| "couldn't extract public key from certificate signing request").unwrap();

        debug!("pkcs10 subject_name: {:?}", pkcs10.subject_name());
        let cname = pkcs10
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .with_context(|| "failed to get common name from csr").unwrap()
            .data()
            .as_utf8()
            .with_context(|| "couldn't convert csr cname to openssl string").unwrap()
            .to_string();

        let cert = crypto.create_cert(&pub_key, &cname, &Some(pkcs10), 1).unwrap();
        std::fs::write("generated_intermediate.crt",&cert.to_pem().unwrap()).unwrap();

        let response = std::process::Command::new("openssl")
            .args(["x509","-text","-in","generated_intermediate.crt","-noout"])
            .output().unwrap().stdout;
        let response = std::str::from_utf8(&response).unwrap();

        assert!(response.contains("CA:TRUE, pathlen:0")); // Basic Constaints CA, pathlen 0 - note that CSR has pathlen 1, this change is intentional.
        assert!(response.contains("DNS:testdomain.de, IP Address:127.0.0.1")); // Subject Alternative Name
        assert!(response.contains("Digital Signature, Certificate Sign, CRL Sign")); // KeyUsage

    }
}
