# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] Q3 2022
- renamed to omnect

## [0.2.0] Q3 2022
- added methods to create a certificate signed request (csr, pkcs#10) from a given client certificate, key pair

## [0.1.3] Q2 2022
- be verbose if certificate verification fails

## [0.1.2] Q2 2022
- fixed verification of newly generated certificates; now it respects ca depth > 1

## [0.1.1] Q1 2022
- `Crypto::create_cert`: verify the new generated certificate against the ca
  chain<br>
  (we could generate a new certificate via a faulty chain before, where the
  issued certificate could not be verified against the ca chain)

## [0.1.0] Q1 2022

Initial Version

- interface to generate new certificate and key pair
- interface to generate new certificate for a given public key
