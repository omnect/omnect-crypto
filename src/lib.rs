use anyhow::{Result};

#[derive(Clone)]
pub struct Crypto {
    pub ca_key: openssl::pkey::PKey<openssl::pkey::Private>,
    pub ca_cert: openssl::x509::X509,
    pub ca_cert_pem: Vec<u8>,
}

impl Crypto {
    pub fn init() {
        openssl::init()
    }
    pub fn new(ca_key: &[u8], ca_cert: &[u8]) -> Result<Self> {
        let ca_cert_pem = ca_cert.to_vec();
        let ca_key = openssl::rsa::Rsa::private_key_from_pem(ca_key)?;
        let ca_key = openssl::pkey::PKey::from_rsa(ca_key)?;
        let ca_cert = openssl::x509::X509::from_pem(ca_cert)?;
        Ok(Crypto {
            ca_key,
            ca_cert,
            ca_cert_pem,
        })
    }
    pub fn new_device(&self, name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = match openssl::rsa::Rsa::generate(4096) {
            Ok(k) => k,
            Err(e) => {
                panic!("Could not generate key: {:?}", e);
            }
        };
        let private_key_pem = key.private_key_to_pem()?;

        let pub_key =
            openssl::rsa::Rsa::from_public_components(key.n().to_owned()?, key.e().to_owned()?)?;

        let pkey = openssl::pkey::PKey::from_rsa(pub_key)?;

        let device_cert = self.new_cert(&pkey, &name)?;
        let device_cert_pem = device_cert.to_pem()?;

        Ok((device_cert_pem, private_key_pem))
    }

    pub fn new_cert(
        &self,
        pub_key: &openssl::pkey::PKey<openssl::pkey::Public>,
        cn: &str,
    ) -> Result<openssl::x509::X509> {
        let serial_number = openssl::bn::BigNum::from_u32(1)?;
        let serial_number_asn = openssl::asn1::Asn1Integer::from_bn(&serial_number)?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365 * 3)?;

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
        let issuer = self.ca_cert.subject_name();
        cert_builder.set_issuer_name(issuer)?;

        // let bc = openssl::x509::extension::BasicConstraints::new()
        //     .pathlen(0)
        //     .build()?;
        let bc = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .build()?;
        cert_builder.append_extension(bc)?;
        // let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        //     .client_auth()
        //     .email_protection()
        //     .build()?;
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
            .build(&cert_builder.x509v3_context(Some(&self.ca_cert), None))?;
        cert_builder.append_extension(ski)?;
        let aki = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&cert_builder.x509v3_context(Some(&self.ca_cert), None))?;
        cert_builder.append_extension(aki)?;
        cert_builder.sign(&self.ca_key, openssl::hash::MessageDigest::sha256())?;
        Ok(cert_builder.build())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn returns_valid_keys_and_certs() -> Result<(), anyhow::Error> {
        let key = match openssl::rsa::Rsa::generate(4096) {
            Ok(k) => k,
            Err(e) => {
                panic!("Could not generate key: {:?}", e);
            }
        };
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
        let bc = openssl::x509::extension::BasicConstraints::new()
            .ca()
            .critical()
            .build()?;
        cert_builder.append_extension(bc)?;
        let ku = openssl::x509::extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()?;
        cert_builder.append_extension(ku)?;
        let ski = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(ski)?;
        let aki = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(aki)?;
        cert_builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
        let ca_cert = cert_builder.build().to_pem()?;

        let crypto = super::Crypto::new(&private_key_pem, &ca_cert)?;
        let (device_cert_pem, device_key_pem) = crypto.new_device("TestDevice")?;

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
