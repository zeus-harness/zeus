#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ApiDoc, PUBLIC_ROUTES, has_oauth_error_response, has_problem_response,
        request_id_from_headers, should_track_http_path, uses_oauth_error_contract,
    };
    use http::{HeaderMap, HeaderValue};
    use utoipa::OpenApi;

    #[test]
    fn public_routes_are_documented_with_unique_operation_ids() {
        let document = ApiDoc::openapi();
        let mut route_keys = BTreeSet::new();
        let mut registered_operation_ids = BTreeSet::new();

        for route in PUBLIC_ROUTES {
            assert!(
                route_keys.insert((route.path, route.method)),
                "duplicate public route {} {}",
                route.method,
                route.path
            );
            let operation = document
                .paths
                .get_path_operation(route.path, route.http_method())
                .unwrap_or_else(|| {
                    panic!("missing OpenAPI operation {} {}", route.method, route.path)
                });
            assert_eq!(
                operation.operation_id.as_deref(),
                Some(route.operation_id),
                "operationId mismatch for {} {}",
                route.method,
                route.path
            );
            assert!(
                operation
                    .responses
                    .responses
                    .contains_key(&route.success_status.to_string()),
                "missing success response for {} {}",
                route.method,
                route.path
            );
            if uses_oauth_error_contract(route.path) {
                assert!(
                    has_oauth_error_response(&operation.responses),
                    "missing OAuth error response for {} {}",
                    route.method,
                    route.path
                );
            } else {
                assert!(
                    has_problem_response(&operation.responses),
                    "missing problem+json response for {} {}",
                    route.method,
                    route.path
                );
            }
            assert!(
                registered_operation_ids.insert(route.operation_id),
                "duplicate operationId {}",
                route.operation_id
            );
        }

        let mut document_operation_ids = BTreeSet::new();
        for path_item in document.paths.paths.values() {
            for operation in [
                &path_item.get,
                &path_item.put,
                &path_item.post,
                &path_item.delete,
                &path_item.options,
                &path_item.head,
                &path_item.patch,
                &path_item.trace,
            ]
            .into_iter()
            .flatten()
            {
                let operation_id = operation
                    .operation_id
                    .as_deref()
                    .expect("every OpenAPI operation has an operationId");
                assert!(
                    document_operation_ids.insert(operation_id),
                    "duplicate document operationId {operation_id}"
                );
            }
        }
        assert_eq!(document_operation_ids, registered_operation_ids);
    }

    #[test]
    fn openapi_declares_security_schemes_and_no_reserved_contract() {
        let openapi = ApiDoc::openapi();
        let components = openapi.components.as_ref().expect("OpenAPI components");
        assert!(components.security_schemes.contains_key("sessionCookie"));
        assert!(
            components
                .security_schemes
                .contains_key("serviceAccountBearer")
        );
        let document = openapi.to_json().expect("valid OpenAPI JSON");
        assert!(!document.contains("The contract is reserved"));
        assert!(!document.contains("\"501\""));
    }

    #[test]
    fn operational_probes_do_not_create_http_pressure() {
        assert!(!should_track_http_path("/health/live"));
        assert!(!should_track_http_path("/health/ready"));
        assert!(!should_track_http_path("/metrics"));
        assert!(should_track_http_path("/api/v1/runs"));
        assert!(should_track_http_path("/auth/login"));
    }

    #[test]
    fn request_ids_accept_only_uuid_v7_values() {
        let request_id = uuid::Uuid::now_v7();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&request_id.to_string()).expect("valid header"),
        );
        assert_eq!(request_id_from_headers(&headers), Some(request_id));

        headers.insert("x-request-id", HeaderValue::from_static("not-a-uuid"));
        assert_eq!(request_id_from_headers(&headers), None);
    }
}
