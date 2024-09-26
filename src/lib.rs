#![warn(clippy::pedantic, clippy::nursery, clippy::all)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]

use std::path::Path;
use std::process::Command;

use keys::Keys;

mod cert;
mod keys;

/// # Errors
/// todo
pub async fn create_pem_files() -> Result<(), String> {
	// set env RUST_BACKTRACE=1
	std::env::set_var("RUST_BACKTRACE", "1");
	let mut keys = Keys::new();
	keys.tls_cert().await;
	let keys_exists = keys.tls_certificate.clone().ok_or("Error: TLS Certificate Not Found.")?.pem_exists();

	if keys_exists {
		Ok(())
	} else {
		keys.tls_certificate.clone().ok_or("Error: TLS Certificate Not Found.")?.create_dirs();

		let cert = keys.tls_certificate.clone().ok_or("Error: TLS Certificate Not Found.")?.clone();
		let tls_cert_pem_path = Path::new(cert.pem_path.as_str());
		let tls_key_pem_path = Path::new(cert.key.as_str());
		let tls_rsa_key_pem_path = Path::new(cert.rsa_key.as_str());

		// # OpenSSL
		// Use OpenSSL to generate the TLS certificate and key files from the TLS certificate .p12 file. Then use OpenSSL to generate the RSA encoded key file from the TLS key .pem file.

		// generate cert
		return match Command::new("openssl").arg("pkcs12").arg("-in").arg(keys.tls_cert_path().await).arg("-out").arg(tls_cert_pem_path.as_os_str()).arg("-clcerts").arg("-nokeys").arg("-passin").arg("pass:").output() {
			Ok(output) => {
				return if output.status.success() {
					// generate key
					return match Command::new("openssl").arg("pkcs12").arg("-in").arg(keys.tls_cert_path().await).arg("-out").arg(tls_key_pem_path.as_os_str()).arg("-passin").arg("pass:").arg("-nodes").output() {
						Ok(output) => {
							return if output.status.success() {
								// generate rsa key
								return match Command::new("openssl").arg("rsa").arg("-in").arg(tls_key_pem_path.as_os_str()).arg("-out").arg(tls_rsa_key_pem_path.as_os_str()).output() {
									Ok(output) => {
										if output.status.success() {
											Ok(())
										} else {
											Err(format!("Failed generate RSA encoded key from key .pem file: {}", String::from_utf8_lossy(&output.stdout)))
										}
									}
									Err(e) => Err(format!("Failed to generate RSA encoded key: {e}")),
								};
							} else {
								Err(format!("Failed to convert TLS certificate .p12 file to TLS key PEM file: {}", String::from_utf8_lossy(&output.stdout)))
							};
						}
						Err(e) => Err(format!("Failed to generate key: {e}")),
					};
				} else {
					Err(format!("Failed to convert TLS certificate .p12 file to TLS certificate PEM file: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
				};
			}
			Err(e) => Err(format!("Failed to generate TLS certificate PEM file: {e}")),
		};
	}
}
