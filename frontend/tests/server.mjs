// Isolated synthetic HTML responses and static assets only; never contacts Auth.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
const template = await readFile(
  new URL("../../sso/templates/sso/login.html", import.meta.url),
  "utf8",
);
createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1:4178");
  if (url.pathname === "/sso/login/" && req.method === "POST") {
    for await (const _ of req) {
      /* Drain synthetic form submission. */
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<h1>Native POST received</h1>");
    return;
  }
  if (url.pathname === "/sso/login/") {
    const html = template
      .replace("{% load static %}", "")
      .replaceAll(/{% static '([^']+)' %}/g, "/static/$1")
      .replace(
        "{% csrf_token %}",
        '<input type="hidden" name="csrfmiddlewaretoken" value="synthetic-csrf">',
      )
      .replace(
        "{{ next }}",
        "/o/authorize/?state=synthetic&amp;client_id=fixture",
      )
      .replace(
        /{% if error %}\s*<p role="alert">{{ error }}<\/p>\s*{% endif %}/,
        url.searchParams.has("error")
          ? '<p role="alert">Invalid credentials or rate limit</p>'
          : "",
      );
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
    return;
  }
  if (
    ["/static/sso/ui/login.js", "/static/sso/ui/login.css"].includes(
      url.pathname,
    )
  ) {
    const name = url.pathname.split("/").at(-1);
    try {
      res.writeHead(200, {
        "Content-Type": name.endsWith(".js") ? "text/javascript" : "text/css",
      });
      res.end(
        await readFile(
          new URL(`../../sso/static/sso/ui/${name}`, import.meta.url),
        ),
      );
    } catch {
      res.end();
    }
    return;
  }
  res.writeHead(404);
  res.end();
}).listen(4178, "127.0.0.1");
