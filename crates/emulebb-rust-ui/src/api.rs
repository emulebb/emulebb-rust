use super::*;

pub(super) async fn fetch_snapshot(client: &Client, config: &ConnectionConfig) -> Result<Snapshot> {
    get(client, config, &format!("snapshot?limit={SNAPSHOT_LIMIT}")).await
}

pub(super) async fn fetch_preferences(
    client: &Client,
    config: &ConnectionConfig,
) -> Result<Preferences> {
    get(client, config, "app/preferences").await
}

pub(super) async fn update_preferences(
    client: &Client,
    config: &ConnectionConfig,
    request: &PreferencesUpdate,
) -> Result<Preferences> {
    patch_json(client, config, "app/preferences", request).await
}

pub(super) async fn create_search(
    client: &Client,
    config: &ConnectionConfig,
    query: String,
    method: String,
    file_type: String,
) -> Result<SearchDto> {
    let query = query.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
    if query.is_empty() {
        anyhow::bail!("enter a search query");
    }
    let request = SearchCreateRequest {
        query,
        method: normalize_search_method(&method),
        file_type: normalize_search_type(&file_type),
    };
    post_json(client, config, "searches", &request).await
}

pub(super) async fn fetch_search(
    client: &Client,
    config: &ConnectionConfig,
    search_id: &str,
) -> Result<SearchDto> {
    get(
        client,
        config,
        &format!(
            "searches/{search_id}?limit={SEARCH_RESULT_LIMIT}&includeEvidence=false&exactTotal=true"
        ),
    )
    .await
}

pub(super) async fn fetch_latest_search(
    client: &Client,
    config: &ConnectionConfig,
) -> Result<Option<SearchDto>> {
    let searches: SearchListDto = get(client, config, "searches").await?;
    let Some(search_id) = latest_search_id(&searches.items) else {
        return Ok(None);
    };
    fetch_search(client, config, &search_id).await.map(Some)
}

pub(super) async fn download_search_result(
    client: &Client,
    config: &ConnectionConfig,
    search_id: &str,
    hash: &str,
    paused: bool,
) -> Result<()> {
    let request = SearchResultDownloadRequest { paused };
    let _: Value = post_json(
        client,
        config,
        &format!("searches/{search_id}/results/{hash}/operations/download"),
        &request,
    )
    .await?;
    Ok(())
}

pub(super) async fn create_server(
    client: &Client,
    config: &ConnectionConfig,
    request: &ServerCreateRequest,
) -> Result<ServerDto> {
    post_json(client, config, "servers", request).await
}

pub(super) async fn update_server(
    client: &Client,
    config: &ConnectionConfig,
    endpoint: &str,
    request: &ServerUpdateRequest,
) -> Result<ServerDto> {
    patch_json(client, config, &format!("servers/{endpoint}"), request).await
}

pub(super) async fn delete_server(
    client: &Client,
    config: &ConnectionConfig,
    endpoint: &str,
) -> Result<()> {
    delete_operation(client, config, &format!("servers/{endpoint}")).await
}

pub(super) async fn import_servers_url(
    client: &Client,
    config: &ConnectionConfig,
    url: String,
) -> Result<()> {
    let request = UrlImportRequest { url };
    let _: Value = post_json(
        client,
        config,
        "servers/operations/import-met-url",
        &request,
    )
    .await?;
    Ok(())
}

pub(super) async fn kad_operation(
    client: &Client,
    config: &ConnectionConfig,
    action: &str,
) -> Result<()> {
    post_operation(client, config, &format!("kad/operations/{action}")).await
}

pub(super) async fn get<T>(client: &Client, config: &ConnectionConfig, path: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.get(url);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }

    let response = request.send().await.context("REST request failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST response")?;
    if status.is_success() {
        let envelope: Envelope<T> =
            serde_json::from_slice(&bytes).context("failed to decode REST envelope")?;
        Ok(envelope.data)
    } else {
        Err(decode_error(status, &bytes))
    }
}

pub(super) async fn post_json<T, U>(
    client: &Client,
    config: &ConnectionConfig,
    path: &str,
    body: &U,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    U: Serialize + ?Sized,
{
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.post(url).json(body);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }
    let response = request.send().await.context("REST operation failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST operation response")?;
    if status.is_success() {
        let envelope: Envelope<T> =
            serde_json::from_slice(&bytes).context("failed to decode REST envelope")?;
        Ok(envelope.data)
    } else {
        Err(decode_error(status, &bytes))
    }
}

pub(super) async fn patch_json<T, U>(
    client: &Client,
    config: &ConnectionConfig,
    path: &str,
    body: &U,
) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    U: Serialize + ?Sized,
{
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.patch(url).json(body);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }
    let response = request.send().await.context("REST operation failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST operation response")?;
    if status.is_success() {
        let envelope: Envelope<T> =
            serde_json::from_slice(&bytes).context("failed to decode REST envelope")?;
        Ok(envelope.data)
    } else {
        Err(decode_error(status, &bytes))
    }
}

pub(super) async fn post_operation(
    client: &Client,
    config: &ConnectionConfig,
    path: &str,
) -> Result<()> {
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.post(url);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }
    let response = request.send().await.context("REST operation failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST operation response")?;
    if status.is_success() {
        Ok(())
    } else {
        Err(decode_error(status, &bytes))
    }
}

pub(super) async fn delete_operation(
    client: &Client,
    config: &ConnectionConfig,
    path: &str,
) -> Result<()> {
    let url = endpoint(&config.base_url, path)?;
    let mut request = client.delete(url);
    if !config.api_key.trim().is_empty() {
        request = request.header("X-API-Key", config.api_key.trim());
    }
    let response = request.send().await.context("REST operation failed")?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read REST operation response")?;
    if status.is_success() {
        Ok(())
    } else {
        Err(decode_error(status, &bytes))
    }
}

pub(super) fn endpoint(base_url: &str, path: &str) -> Result<Url> {
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    };
    let url = Url::parse(&base).with_context(|| format!("invalid REST base URL: {base_url}"))?;
    url.join(path)
        .with_context(|| format!("invalid REST path: {path}"))
}

pub(super) fn decode_error(status: StatusCode, bytes: &[u8]) -> anyhow::Error {
    match serde_json::from_slice::<ErrorEnvelope>(bytes) {
        Ok(error) => anyhow::anyhow!(
            "REST error {}: {} ({})",
            status.as_u16(),
            error.error.message,
            error.error.code
        ),
        Err(_) => anyhow::anyhow!("REST error {}", status.as_u16()),
    }
}
