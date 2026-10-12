"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError, apiFetch, type Passkey, type User } from "@/lib/api";
import {
  bindPasskeyRegisterClick,
  usePasskeySupport,
  webauthnErrorMessage,
} from "@/lib/webauthn";

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const passkeysOk = usePasskeySupport();
  const addButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const me = await apiFetch<User>("/api/me");
        const list = await apiFetch<Passkey[]>("/api/passkeys");
        if (cancelled) {
          return;
        }
        setUser(me);
        setPasskeys(list ?? []);
      } catch (err) {
        if (cancelled) {
          return;
        }
        if (err instanceof ApiError && err.status === 401) {
          router.replace("/");
          return;
        }
        setMessage(err instanceof ApiError ? err.message : "読み込みに失敗しました");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [router]);

  useEffect(() => {
    const button = addButtonRef.current;
    if (!button || !user || !passkeysOk) {
      return;
    }

    return bindPasskeyRegisterClick(
      button,
      () => {
        setMessage("パスキーを追加しました");
        void refreshPasskeys();
      },
      (err) => {
        console.error("passkey registration failed", err);
        setMessage(webauthnErrorMessage(err));
      },
    );
  }, [user, passkeysOk]);

  async function refreshPasskeys() {
    const me = await apiFetch<User>("/api/me");
    const list = await apiFetch<Passkey[]>("/api/passkeys");
    setUser(me);
    setPasskeys(list ?? []);
  }

  async function onLogout() {
    await apiFetch("/api/auth/logout", { method: "POST" });
    router.replace("/");
  }

  async function onDelete(id: number) {
    if (!confirm("このパスキーを削除しますか？")) {
      return;
    }
    setMessage(null);
    try {
      await apiFetch(`/api/passkeys/${id}`, { method: "DELETE" });
      await refreshPasskeys();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : "削除に失敗しました");
    }
  }

  if (!user) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-16 text-muted">読み込み中...</main>
    );
  }

  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-12">
      <header className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm tracking-[0.28em] text-copper">DASHBOARD</p>
          <h1 className="font-serif mt-2 text-4xl">{user.username}</h1>
          <p className="mt-2 text-sm text-muted">
            登録済みパスキーを管理し、次のログイン手段として使えます。
          </p>
        </div>
        <button
          type="button"
          onClick={onLogout}
          className="rounded-full border px-4 py-2 text-sm text-muted"
        >
          ログアウト
        </button>
      </header>

      <section className="mt-10 rounded-3xl border bg-card p-5 shadow-[0_16px_48px_rgba(28,23,18,0.06)]">
        <h2 className="text-lg">パスキーを追加</h2>
        <p className="mt-1 text-sm text-muted">
          ボタンを押すと、この端末の Touch ID / Face ID / Windows Hello
          などの登録画面が開きます。表示名はパスキーの保存先から自動で付きます。画面が出ないときはもう一度押してください。
        </p>
        {message && (
          <p
            role="alert"
            className="mt-4 rounded-xl bg-copper/10 px-3 py-2 text-sm text-copper-dark"
          >
            {message}
          </p>
        )}
        <div className="mt-4">
          <button
            ref={addButtonRef}
            type="button"
            disabled={!passkeysOk}
            className="rounded-xl bg-copper px-4 py-2.5 text-sm text-paper disabled:opacity-50"
          >
            パスキーを追加
          </button>
        </div>
        {!passkeysOk && (
          <p className="mt-3 text-xs text-muted">
            このブラウザはパスキーに対応していません。Chrome / Safari / Edge で
            http://localhost:3000 を開いてください。
          </p>
        )}
      </section>

      <section className="mt-8">
        <h2 className="text-lg">登録済みのパスキー</h2>
        {passkeys.length === 0 ? (
          <p className="mt-4 rounded-2xl border border-dashed px-4 py-8 text-center text-sm text-muted">
            まだパスキーはありません。上のボタンから追加してください。
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {passkeys.map((item) => (
              <li
                key={item.id}
                className="flex items-center justify-between gap-4 rounded-2xl border bg-card px-4 py-4"
              >
                <div>
                  <p className="font-medium">{item.name}</p>
                  <p className="mt-1 text-xs text-muted">
                    追加: {formatDate(item.createdAt)}
                    {item.lastUsedAt ? ` / 最終利用: ${formatDate(item.lastUsedAt)}` : ""}
                    {item.transports.length > 0 ? ` / ${item.transports.join(", ")}` : ""}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onDelete(item.id)}
                  className="text-sm text-copper-dark"
                >
                  削除
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("ja-JP", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}
