import { adminDeleteAll } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function DELETE(request: Request) {
  return adminDeleteAll(request);
}

export async function POST(request: Request) {
  return adminDeleteAll(request);
}
