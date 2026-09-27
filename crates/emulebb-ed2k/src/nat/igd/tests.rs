use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[test]
fn device_parser_prefers_highest_wan_ip_service_and_resolves_relative_url() {
    let location = Url::parse("http://192.0.2.1:5000/root.xml").unwrap();
    let xml = r#"
        <root xmlns="urn:schemas-upnp-org:device-1-0"><device><serviceList>
          <service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ppp</controlURL></service>
          <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>control/v1</controlURL></service>
          <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>/control/v2</controlURL></service>
        </serviceList></device></root>
    "#;

    let (url, service) = parse_device_description(&location, xml).unwrap();

    assert_eq!(url.as_str(), "http://192.0.2.1:5000/control/v2");
    assert_eq!(service, "urn:schemas-upnp-org:service:WANIPConnection:2");
}

#[test]
fn soap_builder_escapes_mapping_values_and_uses_indefinite_lease() {
    let body = soap_envelope(
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "AddPortMapping",
        &[
            ("NewPortMappingDescription", "eMuleBB & <test>"),
            ("NewLeaseDuration", "0"),
        ],
    );

    assert!(body.contains("eMuleBB &amp; &lt;test&gt;"));
    assert!(body.contains("<NewLeaseDuration>0</NewLeaseDuration>"));
}

#[test]
fn soap_fault_parser_preserves_igd_result_code() {
    let fault = parse_igd_fault(
        "<s:Fault xmlns:s=\"urn:soap\"><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault>",
    )
    .unwrap();

    assert_eq!(fault.code, 725);
    assert_eq!(fault.description, "OnlyPermanentLeasesSupported");
    assert_eq!(
        fault.to_string(),
        "UPnP error 725 (OnlyPermanentLeasesSupported)"
    );
}

#[test]
fn location_parser_is_case_insensitive_and_url_validation_rejects_non_http() {
    let response = "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/root.xml\r\n\r\n";
    assert_eq!(
        extract_location_header(response),
        Some("http://192.0.2.1/root.xml")
    );
    assert!(
        validate_http_url(
            &Url::parse("https://192.0.2.1/root.xml").unwrap(),
            "test URL"
        )
        .is_err()
    );
}

#[test]
fn wildcard_mapping_uses_vpn_bind_address() {
    let config = NatConfig {
        bind_ip: Some("192.0.2.34".to_string()),
        ..NatConfig::default()
    };
    let mapping = MappingSpec {
        name: "ed2k".to_string(),
        local_addr: "0.0.0.0:4662".parse().unwrap(),
        protocol: super::super::TransportProtocol::Tcp,
        exposure: super::super::MappingExposure::Required,
        preferred_external_port: None,
    };

    assert_eq!(
        mapping_internal_ip(&config, &mapping, Ipv4Addr::new(198, 51, 100, 1)).unwrap(),
        Ipv4Addr::new(192, 0, 2, 34)
    );
}

#[tokio::test]
async fn soap_wire_roundtrip_reconciles_and_releases_mapping() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            let body = if request.contains("#GetExternalIPAddress") {
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalIPAddress>203.0.113.44</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
            } else if request.contains("#AddPortMapping") {
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/></s:Body></s:Envelope>"
            } else {
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/></s:Body></s:Envelope>"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            requests.push(request);
        }
        requests
    });
    let gateway = Gateway {
        client: http_client(None, Duration::from_secs(2)).unwrap(),
        control_url: Url::parse(&format!("http://{address}/control")).unwrap(),
        service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
        local_ip: Ipv4Addr::LOCALHOST,
        gateway_ip: Ipv4Addr::LOCALHOST,
    };
    let mapping = MappingSpec {
        name: "eMuleBB & test".to_string(),
        local_addr: "127.0.0.1:4662".parse().unwrap(),
        protocol: super::super::TransportProtocol::Tcp,
        exposure: super::super::MappingExposure::Required,
        preferred_external_port: Some(4663),
    };
    let status = Arc::new(RwLock::new(NatStatus::default()));

    reconcile_gateway(
        &gateway,
        &NatConfig {
            enabled: true,
            ..NatConfig::default()
        },
        std::slice::from_ref(&mapping),
        Arc::clone(&status),
    )
    .await
    .unwrap();
    gateway.delete_mapping(4663, "TCP").await.unwrap();

    let requests = server.await.unwrap();
    assert!(requests[0].contains("#GetExternalIPAddress"));
    assert!(requests[1].contains("#AddPortMapping"));
    assert!(requests[1].contains("<NewExternalPort>4663</NewExternalPort>"));
    assert!(requests[1].contains("<NewInternalClient>127.0.0.1</NewInternalClient>"));
    assert!(requests[1].contains("eMuleBB &amp; test"));
    assert!(requests[1].contains("<NewLeaseDuration>0</NewLeaseDuration>"));
    assert!(requests[2].contains("#DeletePortMapping"));
    let status = status.read().await;
    assert_eq!(status.backend.as_deref(), Some(UPNP_IGD_BACKEND));
    assert_eq!(
        status.mappings[0].external_addr,
        "203.0.113.44:4663".parse().unwrap()
    );
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    loop {
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "HTTP client closed before request completed");
        request.extend_from_slice(&buffer[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        });
        if request.len() >= header_end + content_length.unwrap_or(0) {
            return String::from_utf8(request).unwrap();
        }
    }
}
