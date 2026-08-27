import http from "k6/http";
import { check, fail } from "k6";

const baseUrl = __ENV.BASE_URL;
const fixture = JSON.parse(open(__ENV.FIXTURE_FILE));
const sessionId = open(__ENV.SESSION_FILE).trim();
const workload = JSON.parse(__ENV.MARTY_WORKLOAD_JSON);
const profile = workload.profile;
const operations = new Map(workload.operations.map((operation) => [operation.name, operation]));

function routePattern(route) {
  const escaped = route
    .split(/(\{[a-z0-9_]+\})/g)
    .map((part) => /^\{[a-z0-9_]+\}$/.test(part)
      ? "[^/?#]+"
      : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("");
  return new RegExp(`^${escaped}$`);
}

function assertContractOperation(method, path, operationName) {
  const operation = operations.get(operationName);
  if (!operation) throw new Error(`undeclared workload operation: ${operationName}`);
  const pathname = path.split("?", 1)[0];
  if (operation.method !== method || !routePattern(operation.route).test(pathname)) {
    throw new Error(`workload operation ${operationName} does not match its ${operation.method} ${operation.route} contract`);
  }
}

function scenarioFromProfile(value) {
  const scenario = {
    executor: value.executor,
    exec: "readLifecycle",
    gracefulStop: value.graceful_stop || "30s",
  };
  if (value.executor === "per-vu-iterations") {
    scenario.vus = value.vus;
    scenario.iterations = value.iterations;
    scenario.maxDuration = "5m";
  } else {
    scenario.timeUnit = value.time_unit;
    scenario.preAllocatedVUs = value.pre_allocated_vus;
    scenario.maxVUs = value.max_vus;
    if (value.executor === "constant-arrival-rate") {
      scenario.rate = value.rate;
      scenario.duration = value.duration;
    } else {
      scenario.startRate = value.start_rate;
      scenario.stages = value.stages;
    }
  }
  return scenario;
}

export const options = {
  scenarios: { management_lifecycle: scenarioFromProfile(profile) },
  setupTimeout: "2m",
  teardownTimeout: "2m",
  systemTags: ["status", "method", "name", "scenario", "expected_response", "error_code"],
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
    dropped_iterations: ["count==0"],
  },
  tags: {
    suite: "marty-performance",
    workload: workload.name,
    workload_revision: workload.revision,
  },
};

const headers = {
  "Content-Type": "application/json",
  Cookie: `sessionId=${sessionId}`,
};

function request(method, path, body, operation, expectedStatuses) {
  assertContractOperation(method, path, operation);
  const response = http.request(method, `${baseUrl}${path}`, body === null ? null : JSON.stringify(body), {
    headers,
    tags: { name: operation, operation },
    responseCallback: http.expectedStatuses(...expectedStatuses),
  });
  const passed = check(response, {
    [`${operation} returned an expected status`]: (value) => expectedStatuses.includes(value.status),
  });
  return { response, passed };
}

function responseId(result) {
  if (!result.passed) return null;
  try {
    return result.response.json("id");
  } catch (_) {
    return null;
  }
}

function create(state, key, path, body, operation) {
  const result = request("POST", path, body, operation, [200, 201]);
  const id = responseId(result);
  check(id, { [`${operation} returned a resource id`]: (value) => typeof value === "string" && value.length > 0 });
  if (!id) state.setup_error = operation;
  else state.ids[key] = id;
  return id;
}

export function setup() {
  const state = { ids: {}, setup_error: null };
  const organizationId = create(state, "organization", "/v1/organizations", {
    name: fixture.organization_name,
    display_name: fixture.organization_display_name,
  }, "organization-create");
  if (!organizationId) return state;

  const issuerDid = `did:web:marty.test:orgs:${organizationId}`;
  const trustProfileId = create(state, "trust_profile", "/v1/trust-profiles", {
    organization_id: organizationId,
    name: fixture.trust_profile_name,
    profile_type: "CUSTOM",
    trust_sources: [{
      source_type: "PINNED_ISSUER",
      issuer_did: issuerDid,
      description: "Synthetic performance issuer",
    }],
    allowed_issuers: [issuerDid],
    supported_formats: ["SD_JWT_VC"],
  }, "trust-profile-create");
  if (!trustProfileId) return state;

  const credentialTemplateId = create(state, "credential_template", "/v1/credential-templates", {
    organization_id: organizationId,
    issuer_did: issuerDid,
    name: fixture.credential_template_name,
    credential_type: "EmployeeBadge",
    vct: "https://credentials.marty.dev/EmployeeBadge",
    supported_formats: ["sd_jwt_vc"],
    credential_payload_format: "w3c_vcdm_v2_sd_jwt",
    wallet_configs: [{
      wallet_id: "marty",
      deep_link_scheme: "openid-credential-offer://",
      format_variant: "spruce-vc+sd-jwt",
    }],
    compliance_profile: {
      name: "Synthetic Enterprise VC Compliance",
      compliance_code: "ENTERPRISE_VC",
      credential_format: "sd_jwt_vc",
      frameworks: ["enterprise"],
    },
    schema: {
      type: "object",
      properties: {
        employeeId: { type: "string" },
        givenName: { type: "string" },
        familyName: { type: "string" },
        department: { type: "string" },
      },
      required: ["employeeId", "givenName", "familyName", "department"],
    },
    claims: [
      { name: "employeeId", display_name: "Employee ID", required: true },
      { name: "givenName", display_name: "Given Name", required: true },
      { name: "familyName", display_name: "Family Name", required: true },
      { name: "department", display_name: "Department", required: true },
    ],
  }, "credential-template-create");
  if (!credentialTemplateId) return state;

  const presentationPolicyId = create(state, "presentation_policy", "/v1/presentation-policies", {
    organization_id: organizationId,
    name: fixture.presentation_policy_name,
    purpose: "Synthetic employee access performance workload",
    trust_profile_id: trustProfileId,
    credential_requirements: [{
      credential_template_id: credentialTemplateId,
      display_name: "Synthetic Employee Badge",
      requested_claims: [
        { claim_name: "employeeId", display_name: "Employee ID", required: true },
        { claim_name: "department", display_name: "Department", required: true },
      ],
    }],
  }, "presentation-policy-create");
  if (!presentationPolicyId) return state;

  create(state, "deployment_profile", "/v1/deployment-profiles", {
    organization_id: organizationId,
    name: fixture.deployment_profile_name,
    site_id: fixture.site_id,
    network_mode: "online",
    key_access_mode: "key_vault",
    ux_config: { language: "en", operator_mode: false },
    update_policy: { auto_update: false, rollout_percentage: 100 },
    offline_cache_ttl_hours: 24,
    operator_biometric_authentication_required: false,
    audit_all_events: true,
    default_presentation_policy_id: presentationPolicyId,
    trust_profile_id: trustProfileId,
  }, "deployment-profile-create");
  return state;
}

function get(path, operation) {
  request("GET", path, null, operation, [200]);
}

export function readLifecycle(state) {
  if (state.setup_error) fail(`fixture setup failed at ${state.setup_error}`);
  const organization = encodeURIComponent(state.ids.organization);
  get(`/v1/organizations/${organization}`, "organization-get");
  get("/v1/organizations", "organization-list");
  get(`/v1/trust-profiles/${encodeURIComponent(state.ids.trust_profile)}`, "trust-profile-get");
  get(`/v1/trust-profiles?organization_id=${organization}`, "trust-profile-list");
  get(`/v1/credential-templates/${encodeURIComponent(state.ids.credential_template)}`, "credential-template-get");
  get(`/v1/credential-templates?organization_id=${organization}`, "credential-template-list");
  get(`/v1/presentation-policies/${encodeURIComponent(state.ids.presentation_policy)}`, "presentation-policy-get");
  get(`/v1/presentation-policies?organization_id=${organization}`, "presentation-policy-list");
  get(`/v1/deployment-profiles/${encodeURIComponent(state.ids.deployment_profile)}`, "deployment-profile-get");
  get(`/v1/deployment-profiles?organization_id=${organization}`, "deployment-profile-list");
}

function remove(path, operation) {
  request("DELETE", path, null, operation, [200, 204, 404]);
}

export function teardown(state) {
  if (state.ids.deployment_profile) remove(`/v1/deployment-profiles/${encodeURIComponent(state.ids.deployment_profile)}`, "deployment-profile-delete");
  if (state.ids.presentation_policy) remove(`/v1/presentation-policies/${encodeURIComponent(state.ids.presentation_policy)}`, "presentation-policy-delete");
  if (state.ids.credential_template) remove(`/v1/credential-templates/${encodeURIComponent(state.ids.credential_template)}`, "credential-template-delete");
  if (state.ids.trust_profile) remove(`/v1/trust-profiles/${encodeURIComponent(state.ids.trust_profile)}`, "trust-profile-delete");
  if (state.ids.organization) remove(`/v1/organizations/${encodeURIComponent(state.ids.organization)}`, "organization-delete");
}
