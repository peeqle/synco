use ed25519_dalek::VerifyingKey;
use rustls::server::ParsedCertificate;
// 
// pub fn extract_ed25519_pubkey_from_cert(
//     cert_der: &[u8],
// ) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
//     // let (_, cert) = ParsedCertificate::try_from(cert_der)?;
//     // let spki = cert.tbs_certificate.subject_pki.subject_public_key;
//     // 
//     // // OID для Ed25519: 1.3.101.112
//     // if spki.algorithm.algorithm.to_string() != "1.3.101.112" {
//     //     // Проверка OID
//     //     return Err("Public key is not Ed25519".into());
//     // }
//     // 
//     // // SPKI для Ed25519 - это BIT STRING, первый байт которого - количество неиспользуемых битов (обычно 0)
//     // let key_bytes = spki.subject_public_key.data.as_ref();
//     // if key_bytes.is_empty() {
//     //     return Err("Empty public key data".into());
//     // }
//     // // Пропускаем первый байт (number of unused bits, should be 0 for Ed25519)
//     // let raw_key_bytes = &key_bytes[1..];
//     // if raw_key_bytes.len() != 32 {
//     //     return Err(format!(
//     //         "Invalid Ed25519 public key length: got {} bytes, expected 32",
//     //         raw_key_bytes.len()
//     //     )
//     //     .into());
//     // }
//     // let key_array: [u8; 32] = raw_key_bytes.try_into()?;
//     // Ok(VerifyingKey::from_bytes(&key_array)?)
// }
