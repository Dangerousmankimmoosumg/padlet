import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";

export const runtime = "nodejs";

export async function GET() {
  try {
    return NextResponse.json({ isAdmin: await isAdminRequest() });
  } catch {
    return NextResponse.json({ isAdmin: false });
  }
}
