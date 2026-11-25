import "server-only";

import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  ADMIN_SESSION_SECONDS,
  adminCookieOptions,
  createAdminSession,
  destroyAdminSession,
  isAdminRequest,
} from "@/lib/adminSession";
import { hashPassword, isFourDigitPassword, verifyPassword } from "@/lib/password";
import {
  FORBIDDEN,
  INVALID_ID,
  UNAUTHORIZED,
  consumeRateLimit,
  getClientIp,
  isSameOrigin,
  isUuid,
  jsonError,
  readJsonObject,
  releaseRateLimit,
  serverError,
  tooManyRequests,
} from "@/lib/requestGuard";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const PASTEL_COLORS = [
  "#fef3c7",
  "#dbeafe",
  "#dcfce7",
  "#fce7f3",
  "#f3e8ff",
  "#fed7aa",
  "#e0f2fe",
  "#fae8ff",
];

const BCRYPT_PATTERN = /^\$2[aby]\$\d{2}\$.{53}$/;

const CREATE_LIMIT = { count: 20, seconds: 600 };
const DELETE_LIMIT = { count: 30, seconds: 600 };
const DELETE_FAIL_LIMIT = { count: 5, seconds: 600 };
const LOGIN_LIMIT = { count: 5, seconds: 900 };

const charLength = (value: string) => Array.from(value).length;

export async function createMemo(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    const ip = getClientIp(request);
    if (!(await consumeRateLimit("create", [ip], CREATE_LIMIT.count, CREATE_LIMIT.seconds))) {
      return tooManyRequests(CREATE_LIMIT.seconds);
    }

    const body = await readJsonObject(request);
    if (!body) return jsonError("잘못된 요청 형식입니다.", 400);

    const title = typeof body.title === "string" ? body.title.trim() : "";
    const content = typeof body.content === "string" ? body.content.trim() : "";

    if (!title || !content) {
      return jsonError("제목과 내용을 모두 입력해 주세요.", 400);
    }
    if (charLength(title) > 80 || charLength(content) > 2000) {
      return jsonError("메모가 허용된 길이를 초과했습니다.", 400);
    }
    if (!isFourDigitPassword(body.password)) {
      return jsonError("삭제 비밀번호는 숫자 4자리여야 합니다.", 400);
    }

    let color: string;
    if (body.color === undefined || body.color === null) {
      color = PASTEL_COLORS[Math.floor(Math.random() * PASTEL_COLORS.length)];
    } else if (typeof body.color === "string" && PASTEL_COLORS.includes(body.color)) {
      color = body.color;
    } else {
      return jsonError("허용되지 않은 색상입니다.", 400);
    }

    const passwordHash = await hashPassword(body.password);
    const { data, error } = await getSupabaseAdmin().rpc("create_memo_with_credentials", {
      p_title: title,
      p_content: content,
      p_color: color,
      p_password_hash: passwordHash,
    });
    if (error) throw error;

    return NextResponse.json({ memo: data }, { status: 201 });
  } catch (error) {
    return serverError("POST /api/memos", "메모를 저장하지 못했습니다.", error);
  }
}

export async function deleteMemoAsOwner(request: Request, pathId?: string) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    const ip = getClientIp(request);
    if (!(await consumeRateLimit("delete", [ip], DELETE_LIMIT.count, DELETE_LIMIT.seconds))) {
      return tooManyRequests(DELETE_LIMIT.seconds);
    }

    const body = await readJsonObject(request);
    if (!body) return jsonError("잘못된 요청 형식입니다.", 400);
    const id = pathId ?? body.id;
    if (!isUuid(id)) return INVALID_ID();
    if (!isFourDigitPassword(body.password)) {
      return jsonError("숫자 4자리 비밀번호를 입력해 주세요.", 400);
    }

    // 시도를 먼저 기록하고, 성공하면 되돌립니다. 동시 요청으로 한도를 우회할 수 없습니다.
    const failKey = [id, ip];
    if (
      !(await consumeRateLimit("delete-fail", failKey, DELETE_FAIL_LIMIT.count, DELETE_FAIL_LIMIT.seconds))
    ) {
      return tooManyRequests(DELETE_FAIL_LIMIT.seconds);
    }

    const supabase = getSupabaseAdmin();
    const { data: credential, error: readError } = await supabase
      .from("memo_credentials")
      .select("password_hash")
      .eq("memo_id", id)
      .maybeSingle();
    if (readError) throw readError;
    if (!credential) return jsonError("메모를 찾을 수 없습니다.", 404);

    if (!(await verifyPassword(body.password, credential.password_hash))) {
      return jsonError("삭제 비밀번호가 일치하지 않습니다.", 403);
    }

    const { error: deleteError } = await supabase.from("memos").delete().eq("id", id);
    if (deleteError) throw deleteError;

    await releaseRateLimit("delete-fail", failKey);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return serverError("DELETE memo", "메모를 삭제하지 못했습니다.", error);
  }
}

async function requireAdmin(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();
  if (!(await isAdminRequest())) return UNAUTHORIZED();
  return null;
}

export async function adminDeleteMemo(request: Request, pathId?: string) {
  try {
    const denied = await requireAdmin(request);
    if (denied) return denied;

    const id = pathId ?? (await readJsonObject(request))?.id;
    if (!isUuid(id)) return INVALID_ID();

    const { error } = await getSupabaseAdmin().from("memos").delete().eq("id", id);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    return serverError("admin delete memo", "메모를 강제 삭제하지 못했습니다.", error);
  }
}

export async function adminDeleteAll(request: Request) {
  try {
    const denied = await requireAdmin(request);
    if (denied) return denied;

    const { error } = await getSupabaseAdmin().from("memos").delete().not("id", "is", null);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    return serverError("admin delete all", "전체 메모를 삭제하지 못했습니다.", error);
  }
}

export async function adminLogin(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    const adminHash = process.env.ADMIN_PASSWORD_HASH;
    if (!adminHash || !BCRYPT_PATTERN.test(adminHash)) {
      throw new Error("ADMIN_PASSWORD_HASH 환경 변수가 없거나 bcrypt 형식이 아닙니다.");
    }

    const ip = getClientIp(request);
    if (!(await consumeRateLimit("admin-login", [ip], LOGIN_LIMIT.count, LOGIN_LIMIT.seconds))) {
      return tooManyRequests(LOGIN_LIMIT.seconds);
    }

    const body = await readJsonObject(request);
    if (!body || typeof body.password !== "string" || body.password.length > 200) {
      return jsonError("잘못된 요청 형식입니다.", 400);
    }

    if (!(await verifyPassword(body.password, adminHash))) {
      return jsonError("관리자 비밀번호가 일치하지 않습니다.", 401);
    }

    const token = await createAdminSession();
    await releaseRateLimit("admin-login", [ip]);

    const response = NextResponse.json({ ok: true });
    response.cookies.set(ADMIN_COOKIE, token, adminCookieOptions(ADMIN_SESSION_SECONDS));
    return response;
  } catch (error) {
    return serverError("POST /api/admin/login", "관리자 로그인에 실패했습니다.", error);
  }
}

export async function adminLogout(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    await destroyAdminSession();
    const response = NextResponse.json({ ok: true });
    response.cookies.set(ADMIN_COOKIE, "", adminCookieOptions(0));
    return response;
  } catch (error) {
    return serverError("POST /api/admin/logout", "로그아웃하지 못했습니다.", error);
  }
}
