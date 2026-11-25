import "server-only";

import { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";
import { hmac } from "@/lib/adminSession";

export function jsonError(
  message: string,
  status: number,
  headers?: Record<string, string>,
) {
  return NextResponse.json({ error: message }, { status, headers });
}

export const FORBIDDEN = () => jsonError("허용되지 않은 요청입니다.", 403);
export const UNAUTHORIZED = () => jsonError("관리자 인증이 필요합니다.", 401);
export const INVALID_ID = () => jsonError("잘못된 메모 ID입니다.", 400);

export function tooManyRequests(windowSeconds: number) {
  return jsonError("요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.", 429, {
    "Retry-After": String(windowSeconds),
  });
}

export function serverError(label: string, message: string, error: unknown) {
  // 비밀값이 섞이지 않도록 메시지만 기록합니다.
  console.error(label, error instanceof Error ? error.message : "unknown error");
  return jsonError(message, 500);
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

/**
 * 상태 변경 요청은 브라우저가 보낸 Origin이 요청 URL의 Origin과 같아야 합니다.
 * Next.js는 request.url을 Host/X-Forwarded-* 로 구성하며, Vercel은 이 값을
 * 실제 접속 도메인(프로덕션·Preview 모두)으로 채워 줍니다. 허용 주소를 따로 설정하지 않습니다.
 */
export function isSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

/**
 * Vercel은 X-Forwarded-For / X-Real-IP를 클라이언트가 보낸 값 대신 접속 IP로 덮어씁니다
 * (https://vercel.com/docs/headers/request-headers). 그 외 환경에서는 신뢰 근거가 없으므로
 * 헤더가 없으면 하나의 공용 버킷("unknown")으로 모아 보수적으로 제한합니다.
 */
export function getClientIp(request: Request) {
  const real = request.headers.get("x-real-ip")?.trim();
  if (real) return real;
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded || "unknown";
}

function limitKey(action: string, parts: string[]) {
  return hmac(`limit:${action}:${parts.join(":")}`);
}

/** 시도를 기록하고 허용 여부를 반환합니다. 저장소 오류 시 예외를 던져 작업을 막습니다. */
export async function consumeRateLimit(
  action: string,
  parts: string[],
  limit: number,
  windowSeconds: number,
) {
  const { data, error } = await getSupabaseAdmin().rpc("consume_rate_limit", {
    p_key_hash: limitKey(action, parts),
    p_limit: limit,
    p_window_seconds: windowSeconds,
  });
  if (error) throw error;
  return data === true;
}

export async function releaseRateLimit(action: string, parts: string[]) {
  const { error } = await getSupabaseAdmin().rpc("release_rate_limit", {
    p_key_hash: limitKey(action, parts),
  });
  if (error) console.error("release_rate_limit", error.message);
}

export async function readJsonObject(request: Request) {
  try {
    const body: unknown = await request.json();
    return body && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
