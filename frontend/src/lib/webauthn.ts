"use client";

import { useEffect, useState, useSyncExternalStore } from "react";

export function supportsPasskeys(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === "function"
  );
}

export function usePasskeySupport(): boolean {
  return useSyncExternalStore(
    () => () => undefined,
    supportsPasskeys,
    () => false,
  );
}

/**
 * パスキーログイン UI のモード。
 * - "button": 明示的な「パスキーでログイン」ボタンをクリックして navigator.credentials.get() を呼ぶ（デフォルト）。
 * - "conditional": Conditional UI（autofill）。ユーザー名入力欄をタップ/クリックすると
 *   ブラウザがそのフィールドにパスキー候補を自動サジェストする。
 *
 * NEXT_PUBLIC_PASSKEY_UI_MODE=conditional をビルド時/起動時の環境変数に設定するだけで切り替えられる。
 * 未設定または "button" 以外の値の場合は "button" にフォールバックする。
 */
export type PasskeyUIMode = "button" | "conditional";

export const PASSKEY_UI_MODE: PasskeyUIMode =
  process.env.NEXT_PUBLIC_PASSKEY_UI_MODE === "conditional" ? "conditional" : "button";

/**
 * ブラウザが Conditional UI（mediation: "conditional"）に対応しているかを判定する。
 * 対応判定自体が非同期 API のため Promise を返す。
 */
export async function supportsConditionalUI(): Promise<boolean> {
  if (!supportsPasskeys()) {
    return false;
  }
  const pkc = PublicKeyCredential as unknown as {
    isConditionalMediationAvailable?: () => Promise<boolean>;
  };
  if (typeof pkc.isConditionalMediationAvailable !== "function") {
    return false;
  }
  try {
    return await pkc.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

/**
 * Conditional UI 対応状況を返す React フック。
 * 判定が終わるまでは null（判定中）、以後 true/false。
 */
export function useConditionalUISupport(): boolean | null {
  const [supported, setSupported] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    void supportsConditionalUI().then((result) => {
      if (!cancelled) {
        setSupported(result);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return supported;
}

export type CreationOptionsJSON = {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: Array<{
    id: string;
    type: PublicKeyCredentialType;
    transports?: AuthenticatorTransport[];
  }>;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  hints?: string[];
};

export type RequestOptionsJSON = {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: PublicKeyCredentialType;
    transports?: AuthenticatorTransport[];
  }>;
  userVerification?: UserVerificationRequirement;
  hints?: string[];
};

// WebKit がクリック文脈を失ったとき、次のクリックで fetch せず create/get だけを再実行する。
let pendingCreationOptions: CreationOptionsJSON | null = null;
let pendingRequestOptions: RequestOptionsJSON | null = null;

/**
 * SimpleWebAuthn / Yubico の WebKit 要件:
 * ネイティブ click 内で素の fetch を1回だけ行い、直後に credentials.create() する。
 * React onClick・fetch ラッパー・setState・先読みは使わない。
 */
export function bindPasskeyRegisterClick(
  button: HTMLButtonElement,
  getFriendlyName: () => string,
  onSuccess: () => void,
  onError: (err: unknown) => void,
): () => void {
  const onClick = async (event: Event) => {
    event.preventDefault();
    if (!supportsPasskeys()) {
      onError(new Error("このブラウザはパスキーに対応していません"));
      return;
    }

    let optionsJSON = pendingCreationOptions;
    pendingCreationOptions = null;

    try {
      if (!optionsJSON) {
        const begin = await fetch("/api/passkeys/register/begin", {
          method: "POST",
          credentials: "include",
        });
        optionsJSON = await readJSON<CreationOptionsJSON>(begin);
      }

      const publicKey = parseCreationOptions(optionsJSON);
      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) {
        throw new Error("パスキーの作成が完了しませんでした");
      }

      const friendlyName = getFriendlyName().trim();
      const query = friendlyName ? `?name=${encodeURIComponent(friendlyName)}` : "";
      const finish = await fetch(`/api/passkeys/register/finish${query}`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(serializeCredential(credential as PublicKeyCredential)),
      });
      await readJSON(finish);
      onSuccess();
    } catch (err) {
      if (isNotAllowed(err) && optionsJSON) {
        pendingCreationOptions = optionsJSON;
      }
      onError(err);
    }
  };

  button.addEventListener("click", onClick);
  return () => button.removeEventListener("click", onClick);
}

export function bindPasskeyLoginClick(
  button: HTMLButtonElement,
  onSuccess: () => void,
  onError: (err: unknown) => void,
): () => void {
  const onClick = async (event: Event) => {
    event.preventDefault();
    if (!supportsPasskeys()) {
      onError(new Error("このブラウザはパスキーに対応していません"));
      return;
    }

    let optionsJSON = pendingRequestOptions;
    pendingRequestOptions = null;

    try {
      if (!optionsJSON) {
        const begin = await fetch("/api/passkeys/login/begin", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        });
        optionsJSON = await readJSON<RequestOptionsJSON>(begin);
      }

      const publicKey = parseRequestOptions(optionsJSON);
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) {
        throw new Error("パスキー認証が完了しませんでした");
      }

      const finish = await fetch("/api/passkeys/login/finish", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(serializeCredential(credential as PublicKeyCredential)),
      });
      await readJSON(finish);
      onSuccess();
    } catch (err) {
      if (isNotAllowed(err) && optionsJSON) {
        pendingRequestOptions = optionsJSON;
      }
      onError(err);
    }
  };

  button.addEventListener("click", onClick);
  return () => button.removeEventListener("click", onClick);
}

/**
 * Conditional UI（autofill）でのパスキーログインを開始する。
 * ボタンクリックではなくページ側のタイミング（ユーザー名欄の autocomplete="username webauthn"）
 * から自動的に呼び出す想定。ユーザー名は常に空でリクエストする（discoverable login）。
 *
 * 呼び出し元は unmount 時やモード切替時、パスワードでの通常ログイン開始時などに
 * 戻り値の abort 関数を呼んで進行中のリクエストを中断すること。
 */
export function startConditionalLogin(
  onSuccess: () => void,
  onError: (err: unknown) => void,
): () => void {
  const controller = new AbortController();

  void (async () => {
    try {
      const begin = await fetch("/api/passkeys/login/begin", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: "{}",
        signal: controller.signal,
      });
      const optionsJSON = await readJSON<RequestOptionsJSON>(begin);
      if (controller.signal.aborted) {
        return;
      }

      const publicKey = parseRequestOptions(optionsJSON);
      const credential = await navigator.credentials.get({
        publicKey,
        mediation: "conditional" as CredentialMediationRequirement,
        signal: controller.signal,
      });
      if (!credential) {
        return;
      }

      const finish = await fetch("/api/passkeys/login/finish", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(serializeCredential(credential as PublicKeyCredential)),
        signal: controller.signal,
      });
      await readJSON(finish);
      onSuccess();
    } catch (err) {
      if (controller.signal.aborted || isAbortError(err)) {
        return;
      }
      onError(err);
    }
  })();

  return () => controller.abort();
}

function isAbortError(err: unknown): boolean {
  return Boolean(err && typeof err === "object" && "name" in err && err.name === "AbortError");
}

async function readJSON<T>(res: Response): Promise<T> {
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!res.ok) {
    const message =
      data &&
      typeof data === "object" &&
      "error" in data &&
      typeof (data as { error: unknown }).error === "string"
        ? (data as { error: string }).error
        : "リクエストに失敗しました";
    throw new Error(message);
  }
  return data as T;
}

function isNotAllowed(err: unknown): boolean {
  return Boolean(err && typeof err === "object" && "name" in err && err.name === "NotAllowedError");
}

function parseCreationOptions(
  options: CreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  const native = (
    PublicKeyCredential as unknown as {
      parseCreationOptionsFromJSON?: (
        options: CreationOptionsJSON,
      ) => PublicKeyCredentialCreationOptions;
    }
  ).parseCreationOptionsFromJSON;

  if (typeof native === "function") {
    try {
      return native({
        ...options,
        timeout: options.timeout ?? 60000,
      });
    } catch {
      // Fall through to the manual conversion below.
    }
  }

  return {
    rp: {
      id: options.rp.id,
      name: options.rp.name,
    },
    user: {
      id: toBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    challenge: toBuffer(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout ?? 60000,
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      id: toBuffer(cred.id),
      type: cred.type,
      transports: cred.transports,
    })),
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation,
  };
}

function parseRequestOptions(
  options: RequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  const native = (
    PublicKeyCredential as unknown as {
      parseRequestOptionsFromJSON?: (
        options: RequestOptionsJSON,
      ) => PublicKeyCredentialRequestOptions;
    }
  ).parseRequestOptionsFromJSON;

  if (typeof native === "function") {
    try {
      return native({
        ...options,
        timeout: options.timeout ?? 60000,
      });
    } catch {
      // Fall through to the manual conversion below.
    }
  }

  return {
    challenge: toBuffer(options.challenge),
    timeout: options.timeout ?? 60000,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      id: toBuffer(cred.id),
      type: cred.type,
      transports: cred.transports,
    })),
    userVerification: options.userVerification,
  };
}

function serializeCredential(credential: PublicKeyCredential) {
  const withJSON = credential as PublicKeyCredential & {
    toJSON?: () => unknown;
  };
  if (typeof withJSON.toJSON === "function") {
    return withJSON.toJSON();
  }

  const response = credential.response as
    | AuthenticatorAttestationResponse
    | AuthenticatorAssertionResponse;
  const attestation = response as AuthenticatorAttestationResponse;
  const assertion = response as AuthenticatorAssertionResponse;
  const transports =
    typeof attestation.getTransports === "function"
      ? attestation.getTransports()
      : undefined;

  return {
    id: credential.id,
    rawId: toBase64URL(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64URL(response.clientDataJSON),
      attestationObject:
        "attestationObject" in attestation
          ? toBase64URL(attestation.attestationObject)
          : undefined,
      authenticatorData:
        "authenticatorData" in assertion
          ? toBase64URL(assertion.authenticatorData)
          : undefined,
      signature:
        "signature" in assertion ? toBase64URL(assertion.signature) : undefined,
      userHandle:
        "userHandle" in assertion && assertion.userHandle
          ? toBase64URL(assertion.userHandle)
          : undefined,
      transports,
    },
  };
}

function toBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (padded.length % 4)) % 4);
  const raw = atob(padded + pad);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes.buffer;
}

function toBase64URL(data: ArrayBuffer | ArrayBufferView): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function webauthnErrorMessage(err: unknown): string {
  const name = err && typeof err === "object" && "name" in err ? String(err.name) : "";
  const message = err instanceof Error ? err.message : "";

  if (name === "NotAllowedError" || name === "AbortError") {
    return "パスキー画面が出ない／拒否された場合は、もう一度ボタンを押してください。Safari では2回押しが必要なことがあります。キャンセルした場合も同じです。http://localhost:3000 を Chrome または Safari で開いてください";
  }
  if (name === "InvalidStateError") {
    return "この認証器は既に登録されています";
  }
  if (name === "NotSupportedError") {
    return "このブラウザまたはデバイスはパスキーに対応していません";
  }
  if (name === "SecurityError") {
    return "セキュリティ要件を満たしていません。http://localhost:3000 で開いてください（IP アドレスや HTTP では動きません）";
  }
  if (name === "TypeError") {
    return `パスキーの設定が不正です: ${message}`;
  }
  if (message) {
    return message;
  }
  return "パスキー操作に失敗しました";
}
