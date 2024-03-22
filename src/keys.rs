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
		let paths = fs::read_dir(cert_path).unwrap();
		let paths: Vec<String> = paths
			.map(|entry| {
				let p = entry.unwrap().path().display().to_string();
				p
			})
			.collect();

		paths[0].clone()
	}

	pub async fn tls_cert_pem_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		azure_key_vault_client.get("tls-cert-pem-path").await.unwrap().value
	}

	pub async fn tls_key_pem_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		azure_key_vault_client.get("tls-key-pem-path").await.unwrap().value
	}

	pub async fn tls_rsa_key_pem_path(&mut self) -> String {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let azure_key_vault_client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap().secret_client();
		azure_key_vault_client.get("tls-rsa-key-pem-path").await.unwrap().value
	}
}
