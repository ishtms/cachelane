import "server-only";

import { isIP } from "node:net";

import { cookies, headers as requestHeaders } from "next/headers";

export const SESSION_COOKIE = "faultlane_session";

export type Role = "owner" | "admin" | "developer" | "viewer";

export type AuthProviders = {
  github: boolean;
  email: boolean;
};

export type Membership = {
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  role: Role;
};

export type SessionView = {
  id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
};

export type SessionResponse = {
  session: SessionView;
  user: { id: string; email: string };
  memberships: Membership[];
};

export type SessionCreated = SessionResponse & { token: string };

export type Member = {
  user_id: string;
  email: string;
  role: Role;
  joined_at: string;
};

export type Invitation = {
  id: string;
  email: string;
  role: Role;
  created_at: string;
  expires_at: string;
};

export type MemberList = {
  members: Member[];
  invitations: Invitation[];
};

export type AuditList = {
  items: Array<{
    id: string;
    actor_user_id: string | null;
    action: string;
    target_type: string;
    target_id: string;
    result: "succeeded" | "denied" | "failed";
    occurred_at: string;
  }>;
};

export type SessionList = { sessions: SessionView[] };

export type IngestKey = {
  id: string;
  display_suffix: string;
  created_at: string;
  revoked_at: string | null;
};

export type ProjectSetup = {
  owner_id: string;
  organization: {
    id: string;
    name: string;
    slug: string;
  };
  project: {
    id: string;
    name: string;
    slug: string;
  };
  ingest_keys: IngestKey[];
};

export type CreatedSetup = {
  setup: ProjectSetup;
  ingest_key: {
    id: string;
    value: string;
    display_suffix: string;
  };
  data_router_url: string;
  configuration: {
    default_game_ini_path: string;
    default_game_ini: string;
    default_engine_ini_path: string;
    default_engine_ini: string;
  };
};

export type ExistingSetup = {
  setup: ProjectSetup;
};

export type ProjectOnboarding = {
  state:
    | "waiting"
    | "received"
    | "processing"
    | "missing_symbols"
    | "readable_issue"
    | "failed"
    | "quarantined";
  event: {
    id: string;
    received_at: string;
    processing_state: string;
  } | null;
  release: {
    id: string | null;
    version: string;
    platform: string | null;
    architecture: string | null;
    configuration: string | null;
  } | null;
  missing_symbols: Array<{
    required_artifact: "pe" | "pdb";
    module: string;
    architecture: string;
    debug_id: string;
    code_id: string | null;
  }>;
  missing_symbols_truncated: boolean;
  commands: {
    check: string;
    scan: string;
    token_environment: string;
    upload: string | null;
  };
  issue_path: string | null;
  diagnostic: {
    code: string;
    message: string;
    retryable: boolean;
  } | null;
};

export type ArtifactUploadToken = {
  id: string;
  project_id: string;
  token: string;
  display_suffix: string;
  created_at: string;
};

export type ProjectDataRules = {
  version: number;
  redaction_patterns: string[];
  indexed_game_data_keys: string[];
  can_edit: boolean;
  reprocessing_request_id: string | null;
};

export type ProjectUsage = {
  authoritative: true;
  enforcement_enabled: boolean;
  policy_version: number;
  policy_state: "standard" | "courtesy" | "overage" | "sampling";
  threshold: "70" | "90" | "100" | "courtesy_exhausted" | null;
  cycle_start: string;
  cycle_end: string;
  accepted_events: number;
  event_limit: number;
  courtesy_limit: number;
  accepted_raw_bytes: number;
  accepted_symbol_bytes: number;
  deleted_raw_bytes: number;
  sampled_raw_events: number;
  estimated_represented_events: number;
  estimates_present: boolean;
  retained_raw_bytes: number;
  symbol_storage_bytes: number;
  artifact_storage_bytes: number;
  artifact_storage_limit_bytes: number;
  organization_projects: number;
  project_limit: number;
  normalized_retention_days: number;
  normalized_retention_limit_days: number;
  raw_retention_days: number;
  raw_retention_limit_days: number;
  courtesy_percent: number;
  paid_overages_enabled: boolean;
  spend_cap_cents: number | null;
  retain_all_raw: boolean;
  can_edit: boolean;
};

export type AlertIntegration = {
  id: string;
  kind: "email" | "discord" | "slack" | "webhook";
  name: string;
  recipient_user_id: string | null;
  endpoint_host: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  signing_secret?: string;
};

export type AlertRule = {
  id: string;
  integration_id: string;
  condition_kind:
    | "first_seen"
    | "regression"
    | "volume"
    | "missing_symbols"
    | "processing_failure"
    | "ingest_silence"
    | "quota";
  environment: string;
  threshold: number | null;
  window_seconds: number | null;
  quiet_start_minute: number | null;
  quiet_end_minute: number | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type ProjectAlerts = {
  enabled: true;
  can_edit: boolean;
  integrations: AlertIntegration[];
  rules: AlertRule[];
  conditions: Array<{
    rule_id: string;
    scope_key: string;
    state: "active" | "inactive";
    generation: number;
    payload: Record<string, unknown>;
    transitioned_at: string;
  }>;
  deliveries: Array<{
    id: string;
    integration_id: string;
    rule_id: string;
    scope_key: string;
    generation: number;
    transition: "triggered" | "recovered";
    state:
      | "pending"
      | "leased"
      | "delivered"
      | "failed"
      | "dead"
      | "suppressed"
      | "unknown";
    attempt: number;
    failure_code: string | null;
    created_at: string;
    delivered_at: string | null;
  }>;
};

export type Distribution = {
  key: string;
  label: string;
  count: number;
  truncated: boolean;
};

export type ProjectOverview = {
  generated_at: string;
  window: {
    start: string;
    end: string;
    days: 30;
  };
  totals: {
    events: number;
    issues: number;
    new_issues: number;
    regressed_issues: number;
  };
  events_over_time: Array<{ day: string; count: number }>;
  top_issues: Array<{
    issue_id: string;
    path: string;
    title: string;
    status: IssueStatus;
    regression_state: RegressionState;
    event_count: number;
    last_seen_at: string;
  }>;
  releases: Distribution[];
  releases_truncated: boolean;
  releases_other_count: number;
  platforms: Distribution[];
  platforms_truncated: boolean;
  platforms_other_count: number;
  crash_types: Distribution[];
  crash_types_truncated: boolean;
  crash_types_other_count: number;
  symbolication: {
    readable: number;
    partial: number;
    missing: number;
    failed: number;
    processing: number;
    denominator: number;
    success_percent: number | null;
  };
  missing_symbol_count: number;
  ingest: {
    last_received_at: string | null;
    events_in_window: number;
    stored_or_received: number;
  };
  processing: {
    pending_jobs: number;
    leased_jobs: number;
    failed_jobs: number;
    dead_jobs: number;
    oldest_pending_at: string | null;
    states: Distribution[];
  };
  observed_usage: {
    authoritative: false;
    cycle_start: string;
    accepted_events: number;
    retained_raw_bytes: number;
    project_artifact_bytes: number;
    organization_projects: number;
  };
};

export type IssueStatus = "open" | "resolved";
export type RegressionState =
  "new" | "ongoing" | "resolved" | "regressed" | "unknown";
export type SymbolicationState =
  "readable" | "partial" | "missing" | "failed" | "processing";

export type PublicDemoInfo = {
  title: string;
  engine: string;
  synthetic: true;
  read_only: true;
  issue_count: number;
  last_seen_at: string | null;
};

export type PublicDemoIssueSummary = {
  key: string;
  path: string;
  title: string;
  fingerprint: string;
  fingerprint_version: number;
  status: IssueStatus;
  regression_state: RegressionState;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  affected_release_count: number;
  symbolication_state: SymbolicationState;
  crash_type: string | null;
  reprocessed: boolean;
};

export type PublicDemoIssueList = {
  synthetic: true;
  read_only: true;
  items: PublicDemoIssueSummary[];
  truncated: boolean;
};

export type PublicDemoIssueDetail = PublicDemoIssueSummary & {
  synthetic: true;
  read_only: true;
  variants: Array<{
    fingerprint: string;
    first_seen_at: string;
    last_seen_at: string;
    event_count: number;
  }>;
  variants_truncated: boolean;
  releases: Array<{
    version: string;
    platform: string;
    architecture: string;
    configuration: string;
    first_seen_at: string;
    last_seen_at: string;
    event_count: number;
  }>;
  releases_truncated: boolean;
  threads: Array<{
    thread_id: number;
    faulting: boolean;
    frames: Array<{
      module: string | null;
      function: string | null;
      source_file: string | null;
      source_line: number | null;
      inlines: Array<{
        function: string;
        source_file: string | null;
        source_line: number | null;
      }>;
      inlines_truncated: boolean;
    }>;
    frames_truncated: boolean;
  }>;
  threads_truncated: boolean;
  missing_symbols: Array<{
    required_artifact: string;
    module: string;
    architecture: string;
  }>;
  missing_symbols_truncated: boolean;
};

export type IssueSummary = {
  issue_id: string;
  path: string;
  title: string;
  fingerprint_algorithm: string;
  fingerprint_version: number;
  fingerprint: string;
  status: IssueStatus;
  regression_state: RegressionState;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  representative_event_id: string;
  first_release_id: string | null;
  last_release_id: string | null;
  resolved_in_release_id: string | null;
  resolved_at: string | null;
  affected_release_count: number;
};

export type IssueList = {
  items: IssueSummary[];
  next_cursor: string | null;
};

export type IssueDetail = IssueSummary & {
  release_mapping: {
    matched: number;
    missing: number;
    ambiguous: number;
  };
  variants: Array<{
    fingerprint: string;
    first_seen_at: string;
    last_seen_at: string;
    event_count: number;
    representative_event_id: string;
  }>;
  variants_truncated: boolean;
  releases: Array<{
    release_id: string;
    version: string;
    platform: string;
    architecture: string;
    configuration: string;
    build_timestamp: string | null;
    first_seen_at: string;
    last_seen_at: string;
    event_count: number;
    representative_event_id: string;
  }>;
  releases_truncated: boolean;
};

export type EventSummary = {
  event_id: string;
  path: string;
  received_at: string;
  environment: string;
  processing_state: string;
  state_reason: string | null;
  release_id: string | null;
  release_version: string | null;
  crash_type: string | null;
  platform: string | null;
  architecture: string | null;
  engine_version: string | null;
  symbolication_state: SymbolicationState;
  comment_excerpt: string | null;
  comment_truncated: boolean;
  metadata_truncated: boolean;
  current_result_id: string | null;
};

export type EventFacets = {
  releases: Distribution[];
  releases_truncated: boolean;
  releases_other_count: number;
  platforms: Distribution[];
  platforms_truncated: boolean;
  platforms_other_count: number;
  architectures: Distribution[];
  architectures_truncated: boolean;
  architectures_other_count: number;
  environments: Distribution[];
  environments_truncated: boolean;
  environments_other_count: number;
  crash_types: Distribution[];
  crash_types_truncated: boolean;
  crash_types_other_count: number;
  processing_states: Distribution[];
  processing_states_truncated: boolean;
  processing_states_other_count: number;
  custom_context: Array<{
    key: string;
    values: Distribution[];
    values_truncated: boolean;
    values_other_count: number;
  }>;
};

export type EventList = {
  items: EventSummary[];
  next_cursor: string | null;
  facets: EventFacets;
};

export type StackFrame = {
  instruction: string;
  module: string | null;
  module_relative: string | null;
  trust: string;
  symbol_status: string;
  function: string | null;
  source_file: string | null;
  source_line: number | null;
  inlines: Array<{
    function: string;
    source_file: string | null;
    source_line: number | null;
    truncated: boolean;
  }>;
  inlines_truncated: boolean;
  truncated: boolean;
};

export type EventDetail = {
  event: EventSummary;
  crash_guid: string | null;
  crash_guid_truncated: boolean;
  release_mapping: {
    state: string;
    release_id: string | null;
    candidate_release_ids: string[];
    candidate_release_ids_truncated: boolean;
  };
  classification: {
    crash_type: string;
    confidence: string;
    evidence: string[];
    signals: Array<{
      kind: string;
      confidence: string;
      evidence: string[];
      truncated: boolean;
    }>;
    truncated: boolean;
  } | null;
  error_message: string | null;
  error_message_truncated: boolean;
  build_version: string | null;
  build_version_truncated: boolean;
  build_configuration: string | null;
  build_configuration_truncated: boolean;
  user_comment: string | null;
  user_comment_truncated: boolean;
  game_data: Array<{
    name: string;
    name_truncated: boolean;
    value: string;
    value_truncated: boolean;
  }>;
  game_data_truncated: boolean;
  system_context: Array<{
    name: string;
    name_truncated: boolean;
    value: string;
    value_truncated: boolean;
  }>;
  system_context_truncated: boolean;
  log: {
    name: string;
    text: string;
    truncated: boolean;
    invalid_utf8: boolean;
    download_path: string;
  } | null;
  threads: Array<{
    thread_id: number;
    faulting: boolean;
    name: string | null;
    name_truncated: boolean;
    unwind_status: string;
    unwind_status_truncated: boolean;
    frames_truncated: boolean;
    frames: StackFrame[];
  }>;
  threads_truncated: boolean;
  missing_symbols: Array<{
    required_artifact: "pe" | "pdb";
    module: string;
    architecture: string;
    debug_id: string;
    code_id: string | null;
    release_id: string;
    release_version: string;
    truncated: boolean;
  }>;
  missing_symbols_truncated: boolean;
  remediation_command: string | null;
  processing_history: {
    results: Array<{
      result_id: string;
      schema_version: number;
      processing_version: number;
      data_rules_version: number;
      checksum: string;
      created_at: string;
      current: boolean;
    }>;
    results_truncated: boolean;
    requests: Array<{
      request_id: string;
      source: "automatic" | "manual";
      state: "queued" | "running" | "completed" | "failed";
      failure_code: string | null;
      created_at: string;
      completed_at: string | null;
    }>;
    requests_truncated: boolean;
  };
  raw_available: boolean;
};

export type ReprocessingRequest = {
  request_id: string;
  state: string;
  selected_count: number;
  queued_count: number;
  running_count: number;
  completed_count: number;
  failed_count: number;
};

type ApiErrorBody = {
  code?: string;
};

export class FaultlaneApiError extends Error {
  constructor(
    public readonly code: string,
    public readonly status?: number,
  ) {
    super(code);
  }
}

export { FaultlaneApiError as SetupApiError };

async function authorization(): Promise<string> {
  const session = (await cookies()).get(SESSION_COOKIE)?.value;
  if (session) return `Session ${session}`;
  const secret = process.env.FAULTLANE_BOOTSTRAP_SECRET;
  if (!secret) {
    throw new FaultlaneApiError("bootstrap_unavailable");
  }
  return `Bootstrap ${secret}`;
}

export async function faultlaneFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const apiUrl = process.env.FAULTLANE_API_URL ?? "http://127.0.0.1:8080";
  const baseUrl = new URL(apiUrl);
  const targetUrl = new URL(path, baseUrl);
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    targetUrl.origin !== baseUrl.origin
  ) {
    throw new FaultlaneApiError("invalid_api_path");
  }
  const headers = new Headers(init.headers);
  headers.set("authorization", await authorization());
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  try {
    return await fetch(targetUrl, {
      ...init,
      cache: "no-store",
      headers,
    });
  } catch (error) {
    if (error instanceof FaultlaneApiError) {
      throw error;
    }
    throw new FaultlaneApiError("service_unavailable");
  }
}

export async function faultlanePublicApi<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const apiUrl = process.env.FAULTLANE_API_URL ?? "http://127.0.0.1:8080";
  const baseUrl = new URL(apiUrl);
  const targetUrl = new URL(path, baseUrl);
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    targetUrl.origin !== baseUrl.origin
  ) {
    throw new FaultlaneApiError("invalid_api_path");
  }
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  let response: Response;
  try {
    response = await fetch(targetUrl, {
      ...init,
      cache: "no-store",
      headers,
    });
  } catch {
    throw new FaultlaneApiError("service_unavailable");
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    throw new FaultlaneApiError(body.code ?? "request_failed", response.status);
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export async function publicDemoRequestHeaders(): Promise<HeadersInit> {
  const source = (await requestHeaders()).get("cf-connecting-ip");
  return source && isIP(source) ? { "x-forwarded-for": source } : {};
}

export async function faultlaneApi<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await faultlaneFetch(path, init);
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    throw new FaultlaneApiError(body.code ?? "request_failed", response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const setupApi = faultlaneApi;

export function setupErrorMessage(error: unknown): string {
  if (!(error instanceof FaultlaneApiError)) {
    return "Setup could not be completed. Try again.";
  }

  switch (error.code) {
    case "bootstrap_unavailable":
      return "Local bootstrap setup is not enabled.";
    case "service_unavailable":
      return "The FaultLane API is unavailable.";
    case "setup_conflict":
      return "Initial setup is already complete. Open the existing project instead.";
    case "not_found":
      return "That project or ingest key was not found.";
    case "invalid_request":
      return "Check the setup values and try again.";
    default:
      return "Setup could not be completed. Try again.";
  }
}
