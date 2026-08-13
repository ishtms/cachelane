import "server-only";

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

type ApiErrorBody = {
  code?: string;
};

export class SetupApiError extends Error {
  constructor(public readonly code: string) {
    super(code);
  }
}

export async function setupApi<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const apiUrl = process.env.CACHELANE_API_URL ?? "http://127.0.0.1:8080";
  const secret = process.env.CACHELANE_BOOTSTRAP_SECRET;
  if (!secret) {
    throw new SetupApiError("bootstrap_unavailable");
  }

  let response: Response;
  try {
    response = await fetch(new URL(path, apiUrl), {
      ...init,
      cache: "no-store",
      headers: {
        authorization: `Bootstrap ${secret}`,
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...init.headers,
      },
    });
  } catch {
    throw new SetupApiError("service_unavailable");
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    throw new SetupApiError(body.code ?? "request_failed");
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export function setupErrorMessage(error: unknown): string {
  if (!(error instanceof SetupApiError)) {
    return "Setup could not be completed. Try again.";
  }

  switch (error.code) {
    case "bootstrap_unavailable":
      return "Local bootstrap setup is not enabled.";
    case "service_unavailable":
      return "The CacheLane API is unavailable.";
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
