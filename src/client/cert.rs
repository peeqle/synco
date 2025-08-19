use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use log::{error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::broadcast::DiscoveredDevice;
use crate::consts::{of_type, CommonThreadError, DEFAULT_SIGNING_SERVER_PORT};
use crate::keychain::node::{generate_node_csr, save_node_signed_cert};
use crate::keychain::server::save_server_cert;
use crate::server::model::{ServerResponse, SigningServerRequest};

pub async fn request_ca(_device: &DiscoveredDevice) -> Result<Option<ServerResponse>, CommonThreadError> {
    info!("Requesting CA certificate from device: {}", _device.device_id);

    let response = call_signing_server(SigningServerRequest::FetchCrt, _device).await
        .map_err(|e| {
            error!("Failed to call signing server for CA request from {}: {}", _device.device_id, e);
            format!("Signing server call failed for {}: {}", _device.device_id, e)
        })?;

    if let Some(server_response) = response {
        match server_response {
            ServerResponse::Certificate { cert } => {
                info!("Received CA certificate from {}, saving...", _device.device_id);
                if let Err(e) = save_server_cert(_device.device_id.clone(), cert) {
                    error!("Error while saving server CRT for {}: {}", _device.device_id, e);
                    return Err(e);
                }
                info!("Successfully saved server cert for {}", _device.device_id);
            }
            ServerResponse::Error { message } => {
                error!("Server error during certificate fetch from {}: {}", _device.device_id, message);
                return Err(of_type(&format!("Certificate fetch failed from {}: {}", _device.device_id, message), ErrorKind::Other));
            }
            _ => {
                error!("Unexpected response type for certificate fetch request from {}", _device.device_id);
                return Err(of_type(&format!("Certificate fetch failed from {}: Unexpected response type", _device.device_id), ErrorKind::Other));
            }
        }
    } else {
        error!("No response received from signing server for certificate fetch from {}", _device.device_id);
        return Err(of_type(&format!("Certificate fetch failed from {}: No response from server", _device.device_id), ErrorKind::Other));
    }

    Ok(None)
}

pub async fn request_signed_cert(_device: &DiscoveredDevice) -> Result<(), CommonThreadError> {
    let (csr_pem, node_keypair) = generate_node_csr(_device.device_id.clone())?;

    if let Some(response) = call_signing_server(SigningServerRequest::SignCsr {
        csr: csr_pem
    }, _device).await.expect("Cannot execute call to signing server") {
        match response {
            ServerResponse::SignedCertificate { device_id, cert_pem } => {
                info!("Got CRT: {}", &cert_pem);
                save_node_signed_cert(device_id, cert_pem.as_str(), node_keypair)?;
                return Ok(());
            }
            ServerResponse::Error { message } => {
                error!("Server error during certificate signing: {}", message);
                return Err(of_type(&format!("Certificate signing failed: {}", message), ErrorKind::Other));
            }
            _ => {
                error!("Unexpected response type for certificate signing request");
                return Err(of_type("Certificate signing failed: Unexpected response type", ErrorKind::Other));
            }
        }
    }
    Err(of_type("Certificate signing failed: No response from server", ErrorKind::BrokenPipe))
}

pub async fn call_signing_server(req: SigningServerRequest, _device: &DiscoveredDevice) -> Result<Option<ServerResponse>, CommonThreadError> {
    let server_addr = SocketAddr::new(
        IpAddr::try_from(Ipv4Addr::from_str(&_device.connect_addr.ip().to_string())?)?,
        DEFAULT_SIGNING_SERVER_PORT);

    info!("Connecting to signing server at {} for device {}", server_addr, _device.device_id);

    let mut stream = TcpStream::connect(server_addr).await
        .map_err(|e| format!("Failed to connect to signing server at {}: {}", server_addr, e))?;

    let serialized_req = serde_json::to_vec(&req)?;
    info!("Sending request to signing server: {} bytes", serialized_req.len());

    stream.write_all(serialized_req.as_slice()).await
        .map_err(|e| format!("Failed to send request to signing server: {}", e))?;

    let mut buffer = Vec::new();
    let bytes_read_total = stream.read_to_end(&mut buffer).await
        .map_err(|e| format!("Failed to read response from signing server: {}", e))?;

    info!("Received {} bytes from signing server", bytes_read_total);

    if bytes_read_total == 0 {
        error!("Signing server sent empty response for device {}", _device.device_id);
        return Ok(None);
    }

    match serde_json::from_slice(&buffer[..bytes_read_total]) {
        Ok(resp) => {
            info!("Successfully parsed server response");
            Ok(Some(resp))
        }
        Err(e) => {
            error!("Failed to deserialize server response for device {}. Raw data: '{}', Error: {}", 
                   _device.device_id, String::from_utf8_lossy(&buffer), e);
            Err(format!("Failed to deserialize server response. Raw data: '{}', Error: {}",
                        String::from_utf8_lossy(&buffer), e).into())
        }
    }
}