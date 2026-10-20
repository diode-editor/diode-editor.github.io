#!/usr/bin/env node
/**
 * Вписывает версию diode в футер лендинга.
 *
 *   node scripts/set-diode-version.mjs <версия>     # 0.9.7 или v0.9.7
 *
 * Зовёт его релиз diode (job `site` в .github/workflows/release.yml репозитория
 * редактора) и коммитит результат в main — GitHub Pages выкладывает его сам.
 * Версия статическая, а не из GitHub API на клиенте: API без токена упирается в
 * лимит 60 запросов в час на IP, а кэш ответа держал старую версию после релиза.
 *
 * Падает, если не нашёл в index.html ровно одну ссылку `class="version"`: разметку
 * футера поменяли — чинить здесь, а не молча не обновлять версию.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const input = process.argv[2] ?? "";
const version = input.replace(/^v/, "");
if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error(`usage: set-diode-version.mjs <X.Y.Z>; got "${input}"`);
    process.exit(2);
}

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "index.html");
const html = fs.readFileSync(file, "utf8");
const pattern = /(<a class="version" [^>]*>)[^<]*(<\/a>)/g;
const found = html.match(pattern)?.length ?? 0;
if (found !== 1) {
    console.error(`index.html: expected exactly one <a class="version">, found ${found}`);
    process.exit(1);
}
fs.writeFileSync(file, html.replace(pattern, `$1${version}$2`));
console.log(`index.html: diode ${version}`);
