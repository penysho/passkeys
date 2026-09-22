"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError, apiFetch, type User } from "@/lib/api";
import {
  bindPasskeyLoginClick,
  usePasskeySupport,
  webauthnErrorMessage,
} from "@/lib/webauthn";

type Mode = "login" | "register";

export default function HomePage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passkeysOk = usePasskeySupport();
  const passkeyButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    apiFetch<User>("/api/me")
      .then(() => router.replace("/dashboard"))
      .catch(() => undefined);
  }, [router]);

  useEffect(() => {
    const button = passkeyButtonRef.current;
    if (!button || !passkeysOk || mode !== "login") {
      return;
    }

    return bindPasskeyLoginClick(
      button,
      () => {
        router.push("/dashboard");
      },
      (err) => {
        console.error("passkey login failed", err);
        setMessage(webauthnErrorMessage(err));
      },
    );
  }, [passkeysOk, mode, router]);

  async function onPasswordSubmit(event: FormEvent) {
    event.preventDefault();
    setMessage(null);
    setBusy(true);
    try {
      const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      await apiFetch<User>(path, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      router.push("/dashboard");
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : "処理に失敗しました");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-full w-full max-w-6xl flex-col gap-10 px-6 py-12 lg:flex-row lg:items-center lg:py-20">
      <section className="flex-1">
        <p className="text-sm tracking-[0.28em] text-copper">PASSKEYS DEMO</p>
        <h1 className="font-serif mt-4 max-w-xl text-5xl leading-tight text-ink">
          パスワードでも、
          <br />
          パスキーでも。
        </h1>
        <p className="mt-6 max-w-lg text-base leading-8 text-muted">
          ユーザー名とパスワードでアカウントを作り、あとから Touch ID や Windows Hello、iCloud
          キーチェーンなどのパスキーを追加できます。ログインはどちらの方法でも構いません。
        </p>
        <ul className="mt-8 space-y-3 text-sm text-muted">
          <li>1. 新規登録はパスワードのみ</li>
          <li>2. ログイン後にパスキーを追加・削除</li>
          <li>3. 次回からパスキー単体でログイン可能</li>
        </ul>
      </section>

      <section className="w-full max-w-md rounded-3xl border bg-card p-6 shadow-[0_24px_80px_rgba(28,23,18,0.08)]">
        <div className="grid grid-cols-2 rounded-full bg-paper p-1 text-sm">
          <button
            type="button"
            className={`rounded-full px-4 py-2 transition ${
              mode === "login" ? "bg-ink text-paper" : "text-muted"
            }`}
            onClick={() => setMode("login")}
          >
            ログイン
          </button>
          <button
            type="button"
            className={`rounded-full px-4 py-2 transition ${
              mode === "register" ? "bg-ink text-paper" : "text-muted"
            }`}
            onClick={() => setMode("register")}
          >
            新規登録
          </button>
        </div>

        {message && (
          <p
            role="alert"
            className="mt-4 rounded-xl bg-copper/10 px-3 py-2 text-sm text-copper-dark"
          >
            {message}
          </p>
        )}

        <form className="mt-6 space-y-4" onSubmit={onPasswordSubmit}>
          <label className="block text-sm">
            <span className="text-muted">ユーザー名</span>
            <input
              className="mt-1 w-full rounded-xl border bg-paper px-3 py-2.5 outline-none ring-copper focus:ring-2"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              maxLength={32}
            />
          </label>
          <label className="block text-sm">
            <span className="text-muted">パスワード</span>
            <input
              className="mt-1 w-full rounded-xl border bg-paper px-3 py-2.5 outline-none ring-copper focus:ring-2"
              type="password"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-xl bg-ink px-4 py-3 text-sm text-paper disabled:opacity-50"
          >
            {mode === "login" ? "パスワードでログイン" : "アカウントを作成"}
          </button>
        </form>

        {mode === "login" && (
          <>
            <div className="my-5 flex items-center gap-3 text-xs tracking-widest text-muted">
              <span className="h-px flex-1 bg-line" />
              または
              <span className="h-px flex-1 bg-line" />
            </div>
            <button
              ref={passkeyButtonRef}
              type="button"
              disabled={!passkeysOk}
              className="w-full rounded-xl border border-copper/30 bg-copper/10 px-4 py-3 text-sm text-copper-dark disabled:opacity-50"
            >
              パスキーでログイン
            </button>
            {!passkeysOk && (
              <p className="mt-3 text-xs text-muted">
                このブラウザはパスキーに対応していません。http://localhost:3000 を Chrome /
                Safari / Edge で開いてください。
              </p>
            )}
            <p className="mt-3 text-xs leading-6 text-muted">
              先にダッシュボードでパスキーを追加してください。ボタンを押すと OS
              の認証画面が開きます。画面が出ないときはもう一度押してください。
            </p>
          </>
        )}
      </section>
    </main>
  );
}
