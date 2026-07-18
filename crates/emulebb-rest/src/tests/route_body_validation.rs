use crate::rest_test_support::*;

#[tokio::test]
async fn paused_body_uses_canonical_boolean_validation() {
    let app = test_router();
    let link = "ed2k://|file|PausedBody.bin|1|00112233445566778899aabbccddeeff|/";
    let cases = [r#""true""#, "1", "null"];

    for value in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            format!(r#"{{"link":"{link}","paused":{value}}}"#),
            "paused must be a boolean",
        )
        .await;
    }

    for value in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/searches/1/results/00112233445566778899aabbccddeeff/operations/download",
            format!(r#"{{"paused":{value}}}"#),
            "paused must be a boolean",
        )
        .await;
    }
}

#[tokio::test]
async fn category_create_body_uses_canonical_validation() {
    let app = test_router();
    let cases = [
        (r#"{}"#, "name must be a non-empty string"),
        (r#"{"name":1}"#, "name must be a non-empty string"),
        (r#"{"name":"   "}"#, "name must not be empty"),
        (
            r#"{"name":"Media","path":1}"#,
            "path must be a non-empty string path",
        ),
        (r#"{"name":"Media","path":"   "}"#, "path must not be empty"),
        (
            r#"{"name":"Media","comment":1}"#,
            "comment must be a string",
        ),
        (
            r#"{"name":"Media","color":"green"}"#,
            "color must be null or an RGB integer",
        ),
        (
            r#"{"name":"Media","color":16777216}"#,
            "color must be null or an RGB integer",
        ),
        (
            r#"{"name":"Media","priority":true}"#,
            "priority must be a string or number",
        ),
        (
            r#"{"name":"Media","priority":4294967296}"#,
            "priority must be a supported priority value",
        ),
        (
            r#"{"name":"Media","priority":"auto"}"#,
            "priority must be one of verylow, low, normal, high, veryhigh",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/categories",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn category_patch_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/categories/1";
    let cases = [
        (r#"{}"#, "category PATCH requires at least one field"),
        (r#"{"name":1}"#, "name must be a non-empty string"),
        (r#"{"name":"   "}"#, "name must not be empty"),
        (r#"{"path":1}"#, "path must be a non-empty string path"),
        (r#"{"path":"   "}"#, "path must not be empty"),
        (r#"{"comment":1}"#, "comment must be a string"),
        (r#"{"color":-1}"#, "color must be null or an RGB integer"),
        (
            r#"{"priority":false}"#,
            "priority must be a string or number",
        ),
        (
            r#"{"priority":4294967296}"#,
            "priority must be a supported priority value",
        ),
        (
            r#"{"priority":"auto"}"#,
            "priority must be one of verylow, low, normal, high, veryhigh",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn friend_create_body_uses_canonical_validation() {
    let app = test_router();
    let user_hash = "00112233445566778899aabbccddeeff";
    let long_name = "a".repeat(129);
    let cases = [
        (
            r#"{}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            r#"{"userHash":1}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            r#"{"userHash":"00112233445566778899AABBCCDDEEFF"}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            r#"{"userHash":"00112233445566778899aabbccddee"}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","name":1}}"#),
            "name must be a string",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","name":"bad\u0001name"}}"#),
            "name must be valid UTF-8 without control characters",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","name":"{long_name}"}}"#),
            "name must be at most 128 characters",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/friends",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn search_create_body_uses_canonical_validation() {
    let app = test_router();
    let long_query = "a".repeat(161);
    let cases = [
        (r#"{}"#.to_string(), "query must be a string"),
        (r#"{"query":1}"#.to_string(), "query must be a string"),
        (
            r#"{"query":"   \t   "}"#.to_string(),
            "query must not be empty",
        ),
        (
            r#"{"query":"bad\u0001query"}"#.to_string(),
            "query must be valid UTF-8 without control characters",
        ),
        (
            format!(r#"{{"query":"{long_query}"}}"#),
            "query must be at most 160 characters",
        ),
        (
            r#"{"query":"sample","method":1}"#.to_string(),
            "method must be a string",
        ),
        (
            r#"{"query":"sample","method":"local"}"#.to_string(),
            "method must be one of automatic, server, global, kad",
        ),
        (
            r#"{"query":"sample","type":1}"#.to_string(),
            "type must be a string",
        ),
        (
            r#"{"query":"sample","type":"archive"}"#.to_string(),
            "type is not supported",
        ),
        (
            r#"{"query":"sample","extension":1}"#.to_string(),
            "extension must be a string",
        ),
        (
            r#"{"query":"sample","minSizeBytes":"1"}"#.to_string(),
            "minSizeBytes must be an unsigned number",
        ),
        (
            r#"{"query":"sample","maxSizeBytes":-1}"#.to_string(),
            "maxSizeBytes must be an unsigned number",
        ),
        (
            r#"{"query":"sample","minSizeBytes":10,"maxSizeBytes":9}"#.to_string(),
            "maxSizeBytes must be greater than or equal to minSizeBytes",
        ),
        (
            r#"{"query":"sample","minAvailability":"1"}"#.to_string(),
            "minAvailability must be an unsigned number",
        ),
        (
            r#"{"query":"sample","minAvailability":1000001}"#.to_string(),
            "minAvailability must be an unsigned number in the range 0..1000000",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/searches",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn core_settings_patch_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/app/settings";
    let cases = [
        (
            r#"{}"#,
            "settings PATCH requires at least one settings section",
        ),
        (
            r#"{"core":{}}"#,
            "settings.core PATCH requires at least one core setting",
        ),
        (
            r#"{"core":{"uploadLimitKiBps":0}}"#,
            "uploadLimitKiBps must be an unsigned number in the range 1..4294967294",
        ),
        (
            r#"{"core":{"downloadLimitKiBps":4294967295}}"#,
            "downloadLimitKiBps must be an unsigned number in the range 1..4294967294",
        ),
        (
            r#"{"core":{"maxConnections":"1"}}"#,
            "maxConnections must be an unsigned number in the range 1..2147483647",
        ),
        (
            r#"{"core":{"maxConnectionsPerFiveSeconds":0}}"#,
            "maxConnectionsPerFiveSeconds must be an unsigned number in the range 1..2147483647",
        ),
        (
            r#"{"core":{"maxSourcesPerFile":2147483648}}"#,
            "maxSourcesPerFile must be an unsigned number in the range 1..2147483647",
        ),
        (
            r#"{"core":{"uploadClientDataRate":0}}"#,
            "uploadClientDataRate must be an unsigned number in the range 1..4294967295",
        ),
        (
            r#"{"core":{"maxUploadSlots":65}}"#,
            "maxUploadSlots must be an unsigned number in the range 1..64",
        ),
        (
            r#"{"core":{"uploadSlotElasticPercent":101}}"#,
            "uploadSlotElasticPercent must be an unsigned number in the range 0..100",
        ),
        (
            r#"{"core":{"queueSize":1999}}"#,
            "queueSize must be an unsigned number in the range 2000..10000",
        ),
        (r#"{"core":{"reconnect":1}}"#, "reconnect must be a boolean"),
        (
            r#"{"core":{"addServersFromServer":1}}"#,
            "addServersFromServer must be a boolean",
        ),
        (
            r#"{"core":{"networkEd2k":"false"}}"#,
            "networkEd2k must be a boolean",
        ),
        (
            r#"{"core":{"unsupportedSetting":1}}"#,
            "unknown settings.core field: unsupportedSetting",
        ),
        (r#"{"daemon":1}"#, "daemon must be an object"),
        (
            r#"{"daemon":{}}"#,
            "settings.daemon PATCH requires at least one setting",
        ),
        (
            r#"{"daemon":{"incomingDir":1}}"#,
            "incomingDir must be a non-empty string path",
        ),
        (
            r#"{"daemon":{"incomingDir":"   "}}"#,
            "incomingDir must not be empty",
        ),
        (
            r#"{"daemon":{"unsupportedSetting":1}}"#,
            "unknown settings.daemon field: unsupportedSetting",
        ),
        (
            r#"{"daemon":{"hostnameLookup":{}}}"#,
            "settings.daemon.hostnameLookup PATCH requires at least one setting",
        ),
        (
            r#"{"daemon":{"hostnameLookup":1}}"#,
            "settings.daemon.hostnameLookup must be an object",
        ),
        (
            r#"{"daemon":{"hostnameLookup":{"unsupportedSetting":1}}}"#,
            "unknown settings.daemon.hostnameLookup field: unsupportedSetting",
        ),
        (
            r#"{"daemon":{"hostnameLookup":{"cacheTtlSecs":0}}}"#,
            "settings.daemon.hostnameLookup.cacheTtlSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"daemon":{"hostnameLookup":{"maxLookupsPerTick":0}}}"#,
            "settings.daemon.hostnameLookup.maxLookupsPerTick must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"daemon":{"hostnameLookup":{"tickIntervalSecs":4}}}"#,
            "settings.daemon.hostnameLookup.tickIntervalSecs must be an unsigned number greater than or equal to 5",
        ),
        (
            r#"{"daemon":{"hostnameLookup":{"tickIntervalSecs":"5"}}}"#,
            "settings.daemon.hostnameLookup.tickIntervalSecs must be an unsigned number greater than or equal to 5",
        ),
        (
            r#"{"ed2k":{}}"#,
            "settings.ed2k PATCH requires at least one setting",
        ),
        (
            r#"{"ed2k":{"unsupportedSetting":1}}"#,
            "unknown settings.ed2k field: unsupportedSetting",
        ),
        (
            r#"{"ed2k":{"listenPort":0}}"#,
            "settings.ed2k.listenPort must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"listenPort":"4662"}}"#,
            "settings.ed2k.listenPort must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"maxParallelDownloadPeers":0}}"#,
            "settings.ed2k.maxParallelDownloadPeers must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"keywordServerAttemptBudget":0}}"#,
            "settings.ed2k.keywordServerAttemptBudget must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"exactHashKeywordServerAttemptBudget":0}}"#,
            "settings.ed2k.exactHashKeywordServerAttemptBudget must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"sourceServerAttemptBudget":"1"}}"#,
            "settings.ed2k.sourceServerAttemptBudget must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"deadServerRetries":0}}"#,
            "settings.ed2k.deadServerRetries must be an unsigned number in the range 1..10",
        ),
        (
            r#"{"ed2k":{"deadServerRetries":11}}"#,
            "settings.ed2k.deadServerRetries must be an unsigned number in the range 1..10",
        ),
        (
            r#"{"ed2k":{"deadServerRetries":"1"}}"#,
            "settings.ed2k.deadServerRetries must be an unsigned number in the range 1..10",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{}}}"#,
            "settings.ed2k.uploadQueue PATCH requires at least one setting",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"unsupportedSetting":1}}}"#,
            "unknown settings.ed2k.uploadQueue field: unsupportedSetting",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"activeSlots":0}}}"#,
            "settings.ed2k.uploadQueue.activeSlots must be an unsigned number in the range 1..64",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"activeSlots":65}}}"#,
            "settings.ed2k.uploadQueue.activeSlots must be an unsigned number in the range 1..64",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"elasticPercent":101}}}"#,
            "settings.ed2k.uploadQueue.elasticPercent must be an unsigned number less than or equal to 100",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"elasticUnderfillSecs":0}}}"#,
            "settings.ed2k.uploadQueue.elasticUnderfillSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"waitingTimeoutSecs":0}}}"#,
            "settings.ed2k.uploadQueue.waitingTimeoutSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"grantedTimeoutSecs":0}}}"#,
            "settings.ed2k.uploadQueue.grantedTimeoutSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"uploadTimeoutSecs":"1"}}}"#,
            "settings.ed2k.uploadQueue.uploadTimeoutSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"ed2k":{"uploadQueue":{"sessionTransferPercent":101}}}"#,
            "settings.ed2k.uploadQueue.sessionTransferPercent must be an unsigned number less than or equal to 100",
        ),
        (
            r#"{"kad":{"unsupportedSetting":1}}"#,
            "unknown settings.kad field: unsupportedSetting",
        ),
        (
            r#"{"kad":{"listenPort":0}}"#,
            "settings.kad.listenPort must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"bootstrapMinRoutingContacts":0}}"#,
            "settings.kad.bootstrapMinRoutingContacts must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreKeywordTtlSecs":0}}"#,
            "settings.kad.localStoreKeywordTtlSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreSourceTtlSecs":0}}"#,
            "settings.kad.localStoreSourceTtlSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreNotesTtlSecs":0}}"#,
            "settings.kad.localStoreNotesTtlSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreKeywordCapacity":0}}"#,
            "settings.kad.localStoreKeywordCapacity must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreSourceCapacity":0}}"#,
            "settings.kad.localStoreSourceCapacity must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreNotesCapacity":0}}"#,
            "settings.kad.localStoreNotesCapacity must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreSourcePerFileCapacity":0}}"#,
            "settings.kad.localStoreSourcePerFileCapacity must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"localStoreNotesPerFileCapacity":0}}"#,
            "settings.kad.localStoreNotesPerFileCapacity must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"republishIntervalSecs":0}}"#,
            "settings.kad.republishIntervalSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"publishContactFanout":0}}"#,
            "settings.kad.publishContactFanout must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"udpFirewallCheckIntervalSecs":59}}"#,
            "settings.kad.udpFirewallCheckIntervalSecs must be an unsigned number greater than or equal to 60",
        ),
        (
            r#"{"kad":{"tcpFirewallCheckIntervalSecs":"60"}}"#,
            "settings.kad.tcpFirewallCheckIntervalSecs must be an unsigned number greater than or equal to 60",
        ),
        (
            r#"{"kad":{"snoopQueueDedupWindowSecs":0}}"#,
            "settings.kad.snoopQueueDedupWindowSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"snoopQueueGeneralMaxQueriesPer600s":0}}"#,
            "settings.kad.snoopQueueGeneralMaxQueriesPer600s must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"snoopQueueGeneralDrainCooldownSecs":0}}"#,
            "settings.kad.snoopQueueGeneralDrainCooldownSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"snoopQueueSourceMaxQueriesPer600s":0}}"#,
            "settings.kad.snoopQueueSourceMaxQueriesPer600s must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"snoopQueueSourceDrainCooldownSecs":0}}"#,
            "settings.kad.snoopQueueSourceDrainCooldownSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"kad":{"snoopQueueSourceStopAfterResults":0}}"#,
            "settings.kad.snoopQueueSourceStopAfterResults must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"nat":{"unsupportedSetting":1}}"#,
            "unknown settings.nat field: unsupportedSetting",
        ),
        (
            r#"{"nat":{"ssdpLocalPort":0}}"#,
            "settings.nat.ssdpLocalPort must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"nat":{"backendOrder":"upnp_miniupnpc"}}"#,
            "settings.nat.backendOrder must contain only upnp_miniupnpc",
        ),
        (
            r#"{"nat":{"backendOrder":["upnp_miniupnpc",7]}}"#,
            "settings.nat.backendOrder must contain only upnp_miniupnpc",
        ),
        (
            r#"{"nat":{"backendOrder":["natpmp"]}}"#,
            "settings.nat.backendOrder must contain only upnp_miniupnpc",
        ),
        (
            r#"{"nat":{"discoveryTimeoutSecs":0}}"#,
            "settings.nat.discoveryTimeoutSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"nat":{"leaseDurationSecs":0}}"#,
            "settings.nat.leaseDurationSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"nat":{"renewMarginSecs":0}}"#,
            "settings.nat.renewMarginSecs must be an unsigned number greater than or equal to 1",
        ),
        (
            r#"{"nat":{"bindIp":"not-an-ip"}}"#,
            "settings.nat.bindIp must be an IPv4 address string or null",
        ),
        (
            r#"{"nat":{"igdIp":"2001:db8::1"}}"#,
            "settings.nat.igdIp must be an IPv4 address string or null",
        ),
        (
            r#"{"nat":{"externalIpOverride":203}}"#,
            "settings.nat.externalIpOverride must be an IPv4 address string or null",
        ),
        (
            r#"{"nat":{},"daemon":{"incomingDir":"C:/Incoming"}}"#,
            "settings.nat PATCH requires at least one setting",
        ),
        (
            r#"{"vpnGuard":{"unsupportedSetting":1}}"#,
            "unknown settings.vpnGuard field: unsupportedSetting",
        ),
        (
            r#"{"vpnGuard":{"mode":"enforce"}}"#,
            "settings.vpnGuard.mode must be one of off, block",
        ),
        (
            r#"{"vpnGuard":{"mode":"Block"}}"#,
            "settings.vpnGuard.mode must be one of off, block",
        ),
        (
            r#"{"vpnGuard":{"mode":1}}"#,
            "settings.vpnGuard.mode must be one of off, block",
        ),
        (
            r#"{"ipFilter":{"unsupportedSetting":1}}"#,
            "unknown settings.ipFilter field: unsupportedSetting",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_add_body_keeps_canonical_link_validation_before_paused() {
    let app = test_router();
    let link = "ed2k://|file|PausedOrder.bin|1|00112233445566778899aabbccddeeff|/";
    let cases = [
        (
            r#"{"paused":"true"}"#.to_string(),
            "link or links is required",
        ),
        (
            format!(r#"{{"link":"{link}","links":[],"paused":"true"}}"#),
            "link and links are mutually exclusive",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_add_link_body_uses_canonical_shape_validation() {
    let app = test_router();
    let cases = [
        (r#"{"link":1}"#.to_string(), "link must be a string"),
        (r#"{"link":"   "}"#.to_string(), "link must not be empty"),
        (
            r#"{"link":"ed2k://|file|Bad Link.bin|1|00112233445566778899aabbccddeeff|/"}"#
                .to_string(),
            "link must not contain whitespace",
        ),
        (
            r#"{"link":"http://example.invalid/file"}"#.to_string(),
            "link must start with ed2k://",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_add_links_body_uses_canonical_array_validation() {
    let app = test_router();
    let too_many_links = std::iter::repeat_n(
        r#""ed2k://|file|Many.bin|1|00112233445566778899aabbccddeeff|/""#,
        101,
    )
    .collect::<Vec<_>>()
    .join(",");
    let cases = [
        (
            r#"{"links":"ed2k://"}"#.to_string(),
            "links must be a string array",
        ),
        (r#"{"links":[]}"#.to_string(), "links must not be empty"),
        (
            r#"{"links":[1]}"#.to_string(),
            "links must be a non-empty string array",
        ),
        (
            r#"{"links":[""]}"#.to_string(),
            "links must be a non-empty string array",
        ),
        (
            r#"{"links":["not-ed2k"]}"#.to_string(),
            "links must be a non-empty string array",
        ),
        (
            format!(r#"{{"links":[{too_many_links}]}}"#),
            "links contains too many items",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_patch_body_uses_canonical_mutation_family_validation() {
    let app = test_router();
    let uri = "/api/v1/transfers/00112233445566778899aabbccddeeff";
    let cases = [
        (
            r#"{}"#,
            "transfer PATCH requires priority, categoryId, categoryName, or name",
        ),
        (
            r#"{"priority":"low","name":"Renamed.bin"}"#,
            "transfer PATCH accepts only one mutation family",
        ),
        (
            r#"{"categoryId":0,"name":"Renamed.bin"}"#,
            "transfer PATCH accepts only one mutation family",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_patch_priority_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/transfers/00112233445566778899aabbccddeeff";
    let cases = [
        (r#"{"priority":1}"#, "priority must be a string"),
        (
            r#"{"priority":"release"}"#,
            "priority must be one of auto, verylow, low, normal, high, veryhigh",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_patch_name_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/transfers/00112233445566778899aabbccddeeff";
    let cases = [
        (r#"{"name":1}"#, "name must be a string"),
        (r#"{"name":"   "}"#, "name must not be empty"),
        (
            r#"{"name":"Bad<Name.bin"}"#,
            "name must be a valid eD2K filename",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn shared_file_patch_body_uses_canonical_priority_validation() {
    let app = test_router();
    let uri = "/api/v1/shared-files/00112233445566778899aabbccddeeff";
    let cases = [
        (
            r#"{}"#,
            "shared-file PATCH requires priority, comment, or rating",
        ),
        (r#"{"priority":1}"#, "priority must be a string"),
        (
            r#"{"priority":"veryhigh"}"#,
            "priority must be one of auto, verylow, low, normal, high, release",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn shared_file_patch_body_uses_canonical_comment_rating_validation() {
    let app = test_router();
    let uri = "/api/v1/shared-files/00112233445566778899aabbccddeeff";
    let cases = [
        (r#"{"rating":5}"#, "comment must be a string"),
        (r#"{"comment":1,"rating":5}"#, "comment must be a string"),
        (
            r#"{"comment":"verified"}"#,
            "rating must be an integer between 0 and 5",
        ),
        (
            r#"{"comment":"verified","rating":"5"}"#,
            "rating must be an integer between 0 and 5",
        ),
        (
            r#"{"comment":"verified","rating":6}"#,
            "rating must be an integer between 0 and 5",
        ),
        (
            r#"{"comment":"verified","rating":-1}"#,
            "rating must be an integer between 0 and 5",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn shared_directories_patch_body_uses_canonical_root_validation() {
    let app = test_router();
    let uri = "/api/v1/shared-directories";
    let cases = [
        (r#"{}"#, "roots must be an array"),
        (r#"{"roots":"C:/Shared"}"#, "roots must be an array"),
        (
            r#"{"roots":[1],"confirmReplaceRoots":true}"#,
            "path must be a non-empty string path",
        ),
        (
            r#"{"roots":["   "],"confirmReplaceRoots":true}"#,
            "path must not be empty",
        ),
        (
            r#"{"roots":[{}],"confirmReplaceRoots":true}"#,
            "path must be a non-empty string path",
        ),
        (
            r#"{"roots":[{"path":1}],"confirmReplaceRoots":true}"#,
            "path must be a non-empty string path",
        ),
        (
            r#"{"roots":[{"path":"C:/Shared","depth":1}],"confirmReplaceRoots":true}"#,
            "unknown shared-directory root field: depth",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn destructive_confirmation_bodies_use_canonical_validation() {
    let app = test_router();
    let cases = [
        (
            "POST",
            "/api/v1/app/shutdown",
            r#"{}"#,
            "confirmShutdown must be true",
        ),
        (
            "POST",
            "/api/v1/diagnostics/dumps",
            r#"{"confirmDump":false,"fullMemory":false}"#,
            "confirmDump must be true",
        ),
        (
            "POST",
            "/api/v1/diagnostics/crash-tests",
            r#"{"confirmCrash":"true"}"#,
            "confirmCrash must be true",
        ),
        (
            "POST",
            "/api/v1/transfers/operations/clear-completed",
            r#"{"confirmClearCompleted":false}"#,
            "confirmClearCompleted must be true",
        ),
        (
            "POST",
            "/api/v1/logs/operations/clear",
            r#"{"confirmClearLogs":false}"#,
            "confirmClearLogs must be true",
        ),
        (
            "PATCH",
            "/api/v1/shared-directories",
            r#"{"roots":["C:/Shared"],"confirmReplaceRoots":false}"#,
            "confirmReplaceRoots must be true",
        ),
    ];

    for (method, uri, body, expected_message) in cases {
        assert_invalid_json_response(app.clone(), method, uri, body.to_string(), expected_message)
            .await;
    }
}

#[tokio::test]
async fn diagnostic_dump_body_uses_canonical_full_memory_validation() {
    let app = test_router();
    let cases = [
        (
            r#"{"confirmDump":true,"fullMemory":"false"}"#,
            "fullMemory must be a boolean",
        ),
        (
            r#"{"confirmDump":false,"fullMemory":"false"}"#,
            "confirmDump must be true",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/diagnostics/dumps",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn server_create_body_uses_canonical_validation() {
    let app = test_router();
    let cases = [
        (r#"{}"#, "address must be a non-empty string"),
        (
            r#"{"address":1,"port":4661}"#,
            "address must be a non-empty string",
        ),
        (
            r#"{"address":"   ","port":4661}"#,
            "address must not be empty",
        ),
        (
            r#"{"address":"127.0.0.1"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":"4661"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":0}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":65536}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"name":1}"#,
            "name must be a string when provided",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"priority":1}"#,
            "priority must be a string",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"priority":"veryhigh"}"#,
            "priority must be one of low, normal, high",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"static":"true"}"#,
            "static must be a boolean",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"connect":"true"}"#,
            "connect must be a boolean",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/servers",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn server_patch_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/servers/127.0.0.1:4661";
    let cases = [
        (
            r#"{}"#,
            "server PATCH requires name, priority, static, or enabled",
        ),
        (r#"{"name":1}"#, "name must be a string when provided"),
        (r#"{"priority":1}"#, "priority must be a string"),
        (
            r#"{"priority":"release"}"#,
            "priority must be one of low, normal, high",
        ),
        (r#"{"static":"true"}"#, "static must be a boolean"),
        (r#"{"enabled":"true"}"#, "enabled must be a boolean"),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn url_import_body_uses_canonical_validation() {
    let app = test_router();
    let routes = [
        "POST /api/v1/servers/operations/import-met-url",
        "POST /api/v1/kad/operations/import-nodes-url",
    ];
    let cases = [
        (r#"{}"#, "url must be a non-empty string"),
        (r#"{"url":1}"#, "url must be a non-empty string"),
        (r#"{"url":"   "}"#, "url must not be empty"),
        (
            r#"{"url":"http://example.invalid/\u0001"}"#,
            "url must be valid UTF-8 without control characters",
        ),
        (
            r#"{"url":"http://example.invalid/file name"}"#,
            "url must not contain whitespace",
        ),
        (
            r#"{"url":"ftp://example.invalid/nodes.dat"}"#,
            "url must start with http:// or https://",
        ),
        (r#"{"url":"http:///nodes.dat"}"#, "url must include a host"),
        (r#"{"url":"https://#fragment"}"#, "url must include a host"),
    ];

    for route in routes {
        let (method, uri) = route.split_once(' ').unwrap();
        for (body, expected_message) in cases {
            assert_invalid_json_response(
                app.clone(),
                method,
                uri,
                body.to_string(),
                expected_message,
            )
            .await;
        }
    }
}

#[tokio::test]
async fn kad_bootstrap_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/kad/operations/bootstrap";
    let cases = [
        (r#"{}"#, "address must be a non-empty string"),
        (
            r#"{"address":1,"port":4672}"#,
            "address must be a non-empty string",
        ),
        (
            r#"{"address":"   ","port":4672}"#,
            "address must not be empty",
        ),
        (
            r#"{"address":"203.0.113.10"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"203.0.113.10","port":"4672"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"203.0.113.10","port":0}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"203.0.113.10","port":65536}"#,
            "port must be in the range 1..65535",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(app.clone(), "POST", uri, body.to_string(), expected_message)
            .await;
    }
}
