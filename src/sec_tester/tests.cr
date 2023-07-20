module SecTester
  SUPPORTED_TESTS = {
    "amazon_s3_takeover",
    "angular_csti",
    "backup_locations",
    "broken_saml_auth",
    "brute_force_login",
    "business_constraint_bypass",
    "common_files",
    "cookie_security",
    "csrf",
    "cve_test",
    "date_manipulation",
    "default_login_location",
    "directory_listing",
    # @deprecated Use "xss" instead
    "dom_xss",
    # "email_header_injection",
    "excessive_data_exposure",
    "exposed_couch_db_apis",
    "file_upload",
    "full_path_disclosure",
    "graphql_introspection",
    "header_security",
    "html_injection",
    "http_method_fuzzing",
    "id_enumeration",
    "improper_asset_management",
    "insecure_tls_configuration",
    "jwt",
    "ldapi",
    "lfi",
    "lrrl",
    "mass_assignment",
    "nosql",
    "open_buckets",
    "open_database",
    "osi",
    # "password_reset_poisoning",
    "proto_pollution",
    "retire_js",
    "rfi",
    "secret_tokens",
    "server_side_js_injection",
    "sqli",
    "ssrf",
    "ssti",
    "stored_xss",
    "unvalidated_redirect",
    "version_control_systems",
    "webdav",
    "wordpress",
    "xpathi",
    "xss",
    "xxe",
  }
end
