use anyhow::{Context, Result};
use std::sync::Once;

static OPENSSL_INIT_ONCE: Once = Once::new();

#[derive(Clone)]
pub struct Crypto {
    pub ca_key: openssl::pkey::PKey<openssl::pkey::Private>,
    pub ca_cert_stack: Vec<openssl::x509::X509>,
    pub verify_flags: openssl::x509::verify::X509VerifyFlags,
}

impl Crypto {
    pub fn new(ca_key: &[u8], ca_cert: &[u8]) -> Result<Self> {
        OPENSSL_INIT_ONCE.call_once(|| openssl::init());

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
        extensions: &Option<openssl::stack::Stack<openssl::x509::X509Extension>>,
        days: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = openssl::rsa::Rsa::generate(4096).with_context(|| "Could not generate key.")?;
        let private_key_pem = key.private_key_to_pem()?;

        let pub_key =
            openssl::rsa::Rsa::from_public_components(key.n().to_owned()?, key.e().to_owned()?)?;

        let pkey = openssl::pkey::PKey::from_rsa(pub_key)?;

        let device_cert = self.create_cert(&pkey, &name, &extensions, days)?;
        let device_cert_pem = device_cert.to_pem()?;

        Ok((device_cert_pem, private_key_pem))
    }

    // todo: what i want is to extract the extensions from the csr to
    // handle them in the certificate generation.
    // currently i adapted the certificate generation to what
    // 'aziot-certd' expects, but imho the extensions should be a parameter
    // to crypto::Crypto::create_cert.
    //
    // 'aziot-certd' provides 'BasicConstraints', 'ExtendedKeyUsage' and
    // 'KeyUsage' in its csr.
    //
    // if the extensions are a parameter to create_cert we would need to
    // parse them, so we know which extensions were provided and
    // which we possibly have to add ourselves.  i guess it is to be
    // discussed, if we want to add extensions in this case.
    //
    // currently I'm not able to parse the extensions:
    //
    // let extensions_stack_iter = extensions().unwrap().iter();
    // for extension in extensions_stack_iter {
    //     debug!("pkcs10 extensions: {:?}",&extension.how_to_get_the_extension_content_here?());
    // }
    pub fn create_cert(
        &self,
        pub_key: &openssl::pkey::PKey<openssl::pkey::Public>,
        cn: &str,
        _extensions: &Option<openssl::stack::Stack<openssl::x509::X509Extension>>,
        days: u32,
    ) -> Result<openssl::x509::X509> {
        let serial_number = openssl::bn::BigNum::from_u32(1)?;
        let serial_number_asn = openssl::asn1::Asn1Integer::from_bn(&serial_number)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(days)?;

        let mut subject_name = openssl::x509::X509NameBuilder::new()?;
        subject_name.append_entry_by_text("C", "DE")?;
        subject_name.append_entry_by_text("ST", "BY")?;
        subject_name.append_entry_by_text("O", "conplement AG")?;
        subject_name.append_entry_by_text("CN", cn)?;
        let subject_name = subject_name.build();

        let mut cert_builder = openssl::x509::X509Builder::new()?;
        cert_builder.set_version(2)?;
        cert_builder.set_not_before(&not_before)?;
        cert_builder.set_not_after(&not_after)?;
        cert_builder.set_serial_number(&serial_number_asn)?;
        cert_builder.set_subject_name(&subject_name)?;
        cert_builder.set_pubkey(pub_key)?;
        let ca_cert = self.ca_cert_stack.first().unwrap(); // safe here
        let issuer = ca_cert.subject_name();
        cert_builder.set_issuer_name(issuer)?;

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
}

#[cfg(test)]
mod tests {
    #[test]
    fn returns_valid_keys_and_certs() -> Result<(), anyhow::Error> {
        let key = openssl::rsa::Rsa::generate(4096)?; // doesnt work in test context: .with_context(|| "Could not generate key.")?;
        let private_key_pem = key.private_key_to_pem()?;

        let serial_number = openssl::bn::BigNum::from_u32(1)?;
        let serial_number_asn = openssl::asn1::Asn1Integer::from_bn(&serial_number)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(1)?;

        let mut subject_name = openssl::x509::X509NameBuilder::new()?;
        subject_name.append_entry_by_text("CN", "test_ca_cert")?;
        let subject_name = subject_name.build();
        let mut cert_builder = openssl::x509::X509Builder::new()?;
        cert_builder.set_version(2)?;
        cert_builder.set_not_before(&not_before)?;
        cert_builder.set_not_after(&not_after)?;
        cert_builder.set_serial_number(&serial_number_asn)?;
        cert_builder.set_subject_name(&subject_name)?;
        let pkey = openssl::pkey::PKey::from_rsa(key.clone())?;
        cert_builder.set_pubkey(&pkey)?;
        let issuer = subject_name; // self signed certificate
        cert_builder.set_issuer_name(&issuer)?;
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .ca()
            .critical()
            .build()?;
        cert_builder.append_extension(basic_constraints)?;
        let key_usage = openssl::x509::extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()?;
        cert_builder.append_extension(key_usage)?;
        let subject_key_identitfier = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identitfier)?;
        let authority_key_identifier = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(authority_key_identifier)?;
        cert_builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
        let ca_cert = cert_builder.build().to_pem()?;

        let crypto = super::Crypto::new(&private_key_pem, &ca_cert)?;
        let (device_cert_pem, device_key_pem) =
            crypto.create_cert_and_key("TestDevice", &None, 1)?;

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
}
