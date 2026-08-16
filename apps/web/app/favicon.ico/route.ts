const favicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#173d32"/><path fill="#7cf6c7" d="M9 7h15v5H15v3h8v5h-8v7H9z"/></svg>`;

export function GET() {
  return new Response(favicon, {
    headers: {
      "Cache-Control": "public, max-age=86400",
      "Content-Type": "image/svg+xml",
    },
  });
}
