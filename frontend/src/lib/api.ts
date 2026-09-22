export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function parseBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });

  const data = await parseBody(res);
  if (!res.ok) {
    const message =
      data && typeof data === "object" && "error" in data && typeof data.error === "string"
        ? data.error
        : "リクエストに失敗しました";
    throw new ApiError(message, res.status);
  }
  return data as T;
}

export type User = {
  id: number;
  username: string;
};

export type Passkey = {
  id: number;
  name: string;
  transports: string[];
  createdAt: string;
  lastUsedAt: string | null;
  backupState: boolean;
  userVerified: boolean;
};
