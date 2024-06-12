use std::fs::create_dir_all;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct TlsCert {
	//pub path: String,
	pub pem_path: String,
	pub key: String,
	pub rsa_key: String,
}

impl TlsCert {
	pub fn create_dirs(&self) {
		let pem_path = &self.pem_path;
		let tls_cert_pem_path = Path::new(&pem_path);

		let key_pem_path = &self.key;
		let tls_key_pem_path = Path::new(&key_pem_path);

		let rsa_key_pem_path = &self.rsa_key;
		let tls_rsa_key_pem_path = Path::new(&rsa_key_pem_path);

		// create the directories for the TLS certificate and key files if they do not exist
		if !tls_cert_pem_path.exists() || !tls_key_pem_path.exists() || !tls_rsa_key_pem_path.exists() {
			// create TLS certificate directory & file if they do not exist
			match tls_cert_pem_path.parent() {
				Some(tls_cert_pem_path_parent) => match create_dir_all(tls_cert_pem_path_parent) {
					Ok(()) => match File::create(tls_cert_pem_path) {
						Ok(_) => {}
						Err(e) => panic!("Failed to create TLS certificate PEM file: {e}"),
					},
					Err(e) => panic!("Failed to create directory for tls-cert-pem-path: {e}"),
				},
				None => panic!("Failed to get parent directory of tls-cert-pem-path: {}", tls_cert_pem_path.display()),
			};

			// create TLS key directory & file if they do not exist
			match tls_key_pem_path.parent() {
				Some(tls_key_pem_path_parent) => match create_dir_all(tls_key_pem_path_parent) {
					Ok(()) => match File::create(tls_key_pem_path) {
						Ok(_) => {}
						Err(e) => panic!("Failed to create TLS key PEM file: {e}"),
					},
					Err(e) => panic!("Failed to create directory for tls-key-pem-path: {e}"),
				},
				None => panic!("Failed to get parent directory of tls-key-pem-path: {}", tls_key_pem_path.display()),
			};

			// create TLS RSA encoded key directory & file if they do not exist
			match tls_rsa_key_pem_path.parent() {
				Some(tls_rsa_key_pem_path_parent) => match create_dir_all(tls_rsa_key_pem_path_parent) {
					Ok(()) => match File::create(tls_rsa_key_pem_path) {
						Ok(_) => {}
						Err(e) => {
							panic!("Failed to create TLS RSA encoded key PEM file: {e}")
						}
					},
					Err(e) => {
						panic!("Failed to create directory for tls-rsa-key-pem-path: {e}")
					}
				},
				None => panic!("Failed to get parent directory of tls-rsa-key-pem-path: {}", tls_rsa_key_pem_path.display()),
			};
		}
	}

	pub fn pem_exists(&self) -> bool {
		let pem_path = &self.pem_path;
		let tls_cert_pem_path = Path::new(&pem_path);

		let key_pem_path = &self.key;
		let tls_key_pem_path = Path::new(&key_pem_path);

		let rsa_key_pem_path = &self.rsa_key;
		let tls_rsa_key_pem_path = Path::new(&rsa_key_pem_path);

		tls_cert_pem_path.exists() && tls_key_pem_path.exists() && tls_rsa_key_pem_path.exists()
	}
}
