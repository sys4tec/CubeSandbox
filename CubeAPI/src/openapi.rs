// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

use std::{fs, path::Path};

use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::{
    handlers,
    models::{
        ApiError, ConnectSandbox, CreateSnapshotRequest, CreateTemplateRequest, NewSandbox,
        NewVolume, RebuildTemplateRequest, RefreshRequest, ResumedSandbox, RollbackRequest,
        RollbackResponse, Sandbox, SandboxDetail, SandboxLogEntry, SandboxLogs,
        SandboxLogsV2Response, SandboxState, SandboxVolumeMount, SetTemplateAliasRequest,
        SetTimeoutRequest, SnapshotInfo, SnapshotListItem, TemplateAliasLookupResponse,
        TemplateBuildJob, TemplateBuildStatus, TemplateCompatAdoptResponseView,
        TemplateCompatMatrixView, TemplateCompatRowView, TemplateCompatSummaryView, TemplateDetail,
        TemplateNodeCompatView, TemplateSummary, UpdateSandboxNetworkRequest, Volume,
        VolumeAndToken,
    },
};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "apiKeyAuth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
        );
    }
}

struct E2BV2CompatibilityAddon;

impl Modify for E2BV2CompatibilityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let create = openapi
            .paths
            .paths
            .get("/sandboxes")
            .and_then(|item| item.post.clone());
        if let Some(mut operation) = create {
            operation.operation_id = Some("create_sandbox_v2".to_string());
            if let Some(item) = openapi.paths.paths.get_mut("/v2/sandboxes") {
                item.post = Some(operation);
            }
        }

        let connect = openapi
            .paths
            .paths
            .get("/sandboxes/{sandboxID}/connect")
            .cloned();
        if let Some(mut item) = connect {
            if let Some(operation) = item.post.as_mut() {
                operation.operation_id = Some("connect_sandbox_v2".to_string());
            }
            openapi
                .paths
                .paths
                .insert("/v2/sandboxes/{sandboxID}/connect".to_string(), item);
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "CubeAPI",
        version = "0.1.0",
        description = "E2B-compatible sandbox API server."
    ),
    paths(
        handlers::health::health,
        handlers::templates::list_templates,
        handlers::templates::get_template,
        handlers::templates::get_template_by_alias,
        handlers::templates::create_template,
        handlers::templates::rebuild_template,
        handlers::templates::update_template,
        handlers::templates::set_template_alias,
        handlers::templates::delete_template,
        handlers::templates::start_template_build,
        handlers::templates::get_template_build_status,
        handlers::templates::get_template_build_logs,
        handlers::templates::template_compat,
        handlers::templates::adopt_template_compat_baseline,
        handlers::sandboxes::list_sandboxes,
        handlers::sandboxes::create_sandbox,
        handlers::sandboxes::list_sandboxes_v2,
        handlers::sandboxes::get_sandbox,
        handlers::sandboxes::kill_sandbox,
        handlers::sandboxes::pause_sandbox,
        handlers::sandboxes::resume_sandbox,
        handlers::sandboxes::connect_sandbox,
        handlers::sandboxes::get_sandbox_logs,
        handlers::sandboxes::get_sandbox_logs_v2,
        handlers::sandboxes::set_sandbox_timeout,
        handlers::sandboxes::update_sandbox_network,
        handlers::sandboxes::refresh_sandbox,
        handlers::snapshots::create_snapshot,
        handlers::snapshots::list_snapshots,
        handlers::snapshots::rollback_sandbox,
        handlers::volumes::list_volumes,
        handlers::volumes::create_volume,
        handlers::volumes::get_volume,
        handlers::volumes::delete_volume
    ),
    components(schemas(
        ApiError,
        handlers::health::HealthResponse,
        TemplateSummary,
        TemplateDetail,
        TemplateAliasLookupResponse,
        TemplateBuildJob,
        TemplateBuildStatus,
        CreateTemplateRequest,
        RebuildTemplateRequest,
        SetTemplateAliasRequest,
        TemplateCompatSummaryView,
        TemplateNodeCompatView,
        TemplateCompatRowView,
        TemplateCompatMatrixView,
        TemplateCompatAdoptResponseView,
        SandboxState,
        SandboxVolumeMount,
        crate::models::ListedSandbox,
        SandboxDetail,
        Sandbox,
        NewSandbox,
        ConnectSandbox,
        ResumedSandbox,
        SetTimeoutRequest,
        UpdateSandboxNetworkRequest,
        RefreshRequest,
        SandboxLogEntry,
        SandboxLogs,
        SandboxLogsV2Response,
        CreateSnapshotRequest,
        SnapshotInfo,
        SnapshotListItem,
        RollbackRequest,
        RollbackResponse,
        NewVolume,
        Volume,
        VolumeAndToken
    )),
    modifiers(&SecurityAddon, &E2BV2CompatibilityAddon),
    tags(
        (name = "health", description = "Health and liveness"),
        (name = "templates", description = "Template catalog"),
        (name = "sandboxes", description = "Sandbox lifecycle and logs"),
        (name = "snapshots", description = "Sandbox snapshots"),
        (name = "volumes", description = "Persistent volumes")
    )
)]
struct ApiDoc;

pub fn build_openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

pub fn export_to_file(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let path = path.as_ref();
    let yaml = build_openapi().to_yaml()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, yaml)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_rules_schema_documents_native_and_e2b_shapes() {
        let document = serde_json::to_value(build_openapi()).expect("serialize OpenAPI document");
        let rules =
            &document["components"]["schemas"]["SandboxNetworkConfig"]["properties"]["rules"];
        assert!(
            rules.to_string().contains("SandboxNetworkRulesInput"),
            "network.rules should reference its compatibility input schema"
        );

        let input = &document["components"]["schemas"]["SandboxNetworkRulesInput"];
        let one_of = input["oneOf"]
            .as_array()
            .expect("network rules input should use oneOf");

        assert!(one_of.iter().any(|schema| schema["type"] == "array"));
        assert!(one_of.iter().any(|schema| {
            schema["type"] == "object" && schema["additionalProperties"]["type"] == "array"
        }));
    }

    #[test]
    fn documents_e2b_v2_create_and_connect_operations() {
        let document = serde_json::to_value(build_openapi()).expect("serialize OpenAPI document");

        assert!(document["paths"]["/v2/sandboxes"]["post"].is_object());
        assert!(document["paths"]["/v2/sandboxes/{sandboxID}/connect"]["post"].is_object());
    }
}
