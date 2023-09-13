use std::fs;
use std::sync::Arc;

use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;

use crate::cert::TlsCert;

#[derive(Debug, Clone)]
pub struct Keys {
	pub tls_certificate: Option<TlsCert>,
}

impl Keys {
	pub fn new() -> Self {
		Self { tls_certificate: None }
	}

	pub async fn tls_cert(&mut self) {
		match self.tls_certificate {
			Some(_) => {}
			None => {
				self.tls_certificate = Some(TlsCert { path: self.tls_cert_path().await, pem_path: self.tls_cert_pem_path().await, key_pem_path: self.tls_key_pem_path().await, rsa_key_pem_path: self.tls_rsa_key_pem_path().await });
			}
		}
	}

	pub async fn tls_cert_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		let cert_path = azure_key_vault_client.get("tls-cert-path").await.unwrap().value;

		// debug list files in cert_path
		let paths = fs::read_dir(&cert_path).unwrap();
		for path in paths {
			let path = path.unwrap().path().to_str().unwrap().to_string();
			println!("Name: {}", path.clone());
		}

		let cert_thumbprint = azure_key_vault_client.get("tls-cert-thumbprint").await.unwrap().value.to_uppercase();
		let full_path = format!("{}{}.p12", cert_path, cert_thumbprint);
		println!("tls_cert_path: {}", full_path);
		cert_path
	}

	pub async fn tls_cert_pem_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		let cert_path = azure_key_vault_client.get("tls-cert-pem-path").await.unwrap().value;
		println!("tls-cert-pem-path: {}", cert_path);
		cert_path
	}

	pub async fn tls_key_pem_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		let cert_path = azure_key_vault_client.get("tls-key-pem-path").await.unwrap().value;
		println!("tls-key-pem-path: {}", cert_path);
		cert_path
	}

	pub async fn tls_rsa_key_pem_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		let cert_path = azure_key_vault_client.get("tls-rsa-key-pem-path").await.unwrap().value;
		println!("tls-rsa-key-pem-path: {}", cert_path);
		cert_path
	}
}
