#!/usr/bin/env node
/**
 * Валидатор и сборщик реестра расширений Diode.
 *
 *   node scripts/registry.mjs validate [--base <ref>] [--fetch] [--allow-removals]
 *   node scripts/registry.mjs build [--check]
 *
 * Источник правды — `extensions/<publisher>.<name>.json`, по файлу на расширение;
 * PR-ы правят только их. `build` собирает из них публикуемый вид `registry/v1/`
 * (`index.json` + `meta/<id>.json`), который раздаёт GitHub Pages и читает Diode.
 *
 * НОРМАТИВ формата — `src/vs/platform/extensionManagement/common/registryFormat.ts`
 * в репозитории редактора; здесь его сознательно упрощённое эхо (иначе пришлось бы
 * тащить сюда TypeScript-тулчейн редактора ради валидации двух десятков JSON-ов).
 * Асимметрия строгости намеренная: клиент обязан пережить битую запись (реестр
 * может обогнать выпущенный редактор), реестр обязан её не опубликовать — поэтому
 * здесь фатально всё, включая неизвестные ключи и невалидные semver-диапазоны.
 */

import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

import semver from "semver";

/** Соответствует REGISTRY_SCHEMA_VERSION в registryFormat.ts. */
const SCHEMA_VERSION = 1;

const SRC_DIR = "extensions";
/** Публикуемый вид версионирован по схеме: ломающая смена формата встанет рядом в v2. */
const OUT_DIR = path.join("registry", "v1");

const KINDS = new Set(["proxy-openvsx", "native"]);
const ORIGINS = new Set(["openvsx", "github-release"]);

/**
 * Куда разрешено указывать артефактам. URL приходят из PR недоверенного
 * контрибьютора, а `--fetch` по ним ходит — без списка это SSRF. Список
 * проверяется и на конечном адресе после редиректов, поэтому в нём есть и CDN,
 * куда уводят раздачи: `openvsx.eclipsecontent.org` (open-vsx) и
 * `objects.githubusercontent.com` (github.com/releases/download).
 */
const ARTIFACT_HOSTS = new Set([
    "open-vsx.org",
    "openvsx.eclipsecontent.org",
    "github.com",
    "objects.githubusercontent.com",
    "diode-editor.github.io",
]);

/**
 * Хост этого же репозитория. Свои артефакты сверяем по файлу в рабочем дереве, а
 * не по сети: в PR они ещё не опубликованы (Pages отдаёт только смерженное), так
 * что сетевая проверка была бы обречена ровно на том PR, который их добавляет.
 */
const SELF_HOST = "diode-editor.github.io";

const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 60_000;

const SHA256_RE = /^[0-9a-f]{64}$/;
/** Форма id; регистр НЕ нормализуем: `installFromRegistry` сверяет id с манифестом побайтно. */
const ID_RE = /^[a-z0-9][a-z0-9_-]*\.[a-z0-9][a-z0-9_-]*$/i;

const META_REQUIRED = ["schemaVersion", "id", "publisher", "name", "displayName", "description", "kind", "versions"];
const META_OPTIONAL = ["repository", "license", "homepage", "readme"];
const VERSION_REQUIRED = ["version", "engines", "artifact", "sha256"];
const VERSION_OPTIONAL = ["size", "publishedAt"];

// --- вывод -----------------------------------------------------------------

const inActions = process.env["GITHUB_ACTIONS"] === "true";

/** Печатает ошибку и, в CI, аннотацию — GitHub покажет её прямо на файле в PR. */
function reportErrors(errors) {
    for (const { file, message } of errors) {
        console.error(`${file}: ${message}`);
        if (inActions) console.log(`::error file=${file}::${message}`);
    }
}

// --- канонический JSON -----------------------------------------------------

/**
 * Единственная форма записи публикуемого JSON. Порядок ключей задаётся
 * конструированием объектов ниже, а не порядком в исходнике: форматирование
 * присланного файла не должно протекать в публикуемое и ломать `build --check`.
 */
function canonicalJson(value) {
    return `${JSON.stringify(value, null, 4)}\n`;
}

/** Кладёт ключ, только если значение задано, — чтобы `undefined` не рождал дыр в порядке. */
function put(target, key, value) {
    if (value !== undefined) target[key] = value;
    return target;
}

function canonicalEngines(engines) {
    const out = {};
    put(out, "diode", engines.diode);
    put(out, "vscode", engines.vscode);
    return out;
}

function canonicalArtifact(artifact) {
    const out = { type: "url", url: artifact.url };
    put(out, "origin", artifact.origin);
    return out;
}

function canonicalVersion(version) {
    const out = {
        version: version.version,
        engines: canonicalEngines(version.engines),
        artifact: canonicalArtifact(version.artifact),
        sha256: version.sha256,
    };
    put(out, "size", version.size);
    put(out, "publishedAt", version.publishedAt);
    return out;
}

function canonicalMeta(meta) {
    const out = {
        schemaVersion: SCHEMA_VERSION,
        id: meta.id,
        publisher: meta.publisher,
        name: meta.name,
        displayName: meta.displayName,
        description: meta.description,
        kind: meta.kind,
    };
    put(out, "repository", meta.repository);
    put(out, "license", meta.license);
    put(out, "homepage", meta.homepage);
    put(out, "readme", meta.readme);
    out.versions = meta.versions.map(canonicalVersion);
    return out;
}

// --- чтение исходников -----------------------------------------------------

function listSourceFiles() {
    if (!fs.existsSync(SRC_DIR)) return [];
    return fs
        .readdirSync(SRC_DIR)
        .filter((name) => name.endsWith(".json"))
        .sort()
        .map((name) => path.posix.join(SRC_DIR, name));
}

/** Читает и разбирает исходник. BOM срезаем сами: иначе JSON.parse даёт невнятное «Unexpected token». */
function readSource(file, errors) {
    let text;
    try {
        text = fs.readFileSync(file, "utf8");
    } catch (error) {
        errors.push({ file, message: `cannot read: ${error.message}` });
        return undefined;
    }
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    try {
        return JSON.parse(text);
    } catch (error) {
        errors.push({ file, message: `malformed JSON: ${error.message}` });
        return undefined;
    }
}

// --- валидация -------------------------------------------------------------

function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value) {
    return typeof value === "string" && value.length > 0;
}

function checkKeys(record, where, required, optional, file, errors) {
    for (const key of required) {
        if (record[key] === undefined) errors.push({ file, message: `${where}: missing "${key}"` });
    }
    const known = new Set([...required, ...optional]);
    for (const key of Object.keys(record)) {
        // Неизвестный ключ фатален: опечатка вроде "licence" иначе молча теряется при сборке.
        if (!known.has(key)) errors.push({ file, message: `${where}: unknown key "${key}"` });
    }
}

function validateEngines(value, where, file, errors) {
    if (!isRecord(value)) {
        errors.push({ file, message: `${where}.engines: expected an object` });
        return;
    }
    checkKeys(value, `${where}.engines`, [], ["diode", "vscode"], file, errors);
    if (value.diode === undefined && value.vscode === undefined) {
        errors.push({ file, message: `${where}.engines: at least one of "diode"/"vscode" is required` });
    }
    for (const key of ["diode", "vscode"]) {
        const range = value[key];
        if (range === undefined) continue;
        if (!isNonEmptyString(range) || semver.validRange(range) === null) {
            errors.push({ file, message: `${where}.engines.${key}: not a valid semver range: ${JSON.stringify(range)}` });
        }
    }
}

function validateArtifact(value, where, file, errors) {
    if (!isRecord(value)) {
        errors.push({ file, message: `${where}.artifact: expected an object` });
        return;
    }
    checkKeys(value, `${where}.artifact`, ["type", "url"], ["origin"], file, errors);
    // Публикуемый реестр раздаётся по сети: path-артефакты живут только в локальных
    // каталогах тестов, опубликовать их нельзя — клиент не сможет их достать.
    if (value.type !== "url") {
        errors.push({ file, message: `${where}.artifact.type: must be "url", got ${JSON.stringify(value.type)}` });
    }
    if (value.origin !== undefined && !ORIGINS.has(value.origin)) {
        errors.push({ file, message: `${where}.artifact.origin: must be one of ${[...ORIGINS].join(", ")}` });
    }
    if (!isNonEmptyString(value.url)) {
        errors.push({ file, message: `${where}.artifact.url: expected a non-empty string` });
        return;
    }
    let url;
    try {
        url = new URL(value.url);
    } catch {
        errors.push({ file, message: `${where}.artifact.url: not a valid URL: ${value.url}` });
        return;
    }
    if (url.protocol !== "https:") {
        errors.push({ file, message: `${where}.artifact.url: must be https, got ${url.protocol}` });
    }
    if (!ARTIFACT_HOSTS.has(url.host)) {
        errors.push({ file, message: `${where}.artifact.url: host "${url.host}" is not allowed` });
    }
}

function validateVersion(value, index, file, errors) {
    const where = `versions[${index}]`;
    if (!isRecord(value)) {
        errors.push({ file, message: `${where}: expected an object` });
        return;
    }
    checkKeys(value, where, VERSION_REQUIRED, VERSION_OPTIONAL, file, errors);

    if (!isNonEmptyString(value.version) || semver.valid(value.version) === null) {
        errors.push({ file, message: `${where}.version: not a valid semver version: ${JSON.stringify(value.version)}` });
    }
    validateEngines(value.engines, where, file, errors);
    validateArtifact(value.artifact, where, file, errors);
    if (typeof value.sha256 !== "string" || !SHA256_RE.test(value.sha256)) {
        errors.push({ file, message: `${where}.sha256: expected 64 lowercase hex chars` });
    }
    if (value.size !== undefined && (!Number.isInteger(value.size) || value.size <= 0)) {
        errors.push({ file, message: `${where}.size: expected a positive integer` });
    }
    if (value.publishedAt !== undefined) {
        if (!isNonEmptyString(value.publishedAt) || Number.isNaN(Date.parse(value.publishedAt))) {
            errors.push({ file, message: `${where}.publishedAt: expected an ISO date` });
        }
    }
}

/**
 * Полная проверка одного исходника. `id` берётся из имени файла — оно и есть
 * первичный ключ реестра, поэтому расхождение с полем `id` фатально.
 */
function validateMeta(raw, file, errors) {
    const before = errors.length;
    const id = path.basename(file, ".json");

    if (!isRecord(raw)) {
        errors.push({ file, message: "expected a JSON object" });
        return undefined;
    }
    checkKeys(raw, "root", META_REQUIRED, META_OPTIONAL, file, errors);

    if (raw.schemaVersion !== SCHEMA_VERSION) {
        errors.push({ file, message: `schemaVersion: must be exactly ${SCHEMA_VERSION}, got ${JSON.stringify(raw.schemaVersion)}` });
    }
    if (!ID_RE.test(id)) {
        errors.push({ file, message: `file name is not a valid extension id: ${id}` });
    }
    for (const key of ["publisher", "name", "displayName"]) {
        if (!isNonEmptyString(raw[key])) errors.push({ file, message: `${key}: expected a non-empty string` });
    }
    if (typeof raw.description !== "string") {
        errors.push({ file, message: "description: expected a string" });
    }
    if (!KINDS.has(raw.kind)) {
        errors.push({ file, message: `kind: must be one of ${[...KINDS].join(", ")}, got ${JSON.stringify(raw.kind)}` });
    }
    for (const key of META_OPTIONAL) {
        if (raw[key] !== undefined && !isNonEmptyString(raw[key])) {
            errors.push({ file, message: `${key}: expected a non-empty string` });
        }
    }
    if (isNonEmptyString(raw.publisher) && isNonEmptyString(raw.name)) {
        const expected = `${raw.publisher}.${raw.name}`;
        if (raw.id !== expected) {
            errors.push({ file, message: `id: must be "${expected}" (publisher.name), got ${JSON.stringify(raw.id)}` });
        }
        if (expected !== id) {
            errors.push({ file, message: `id "${expected}" does not match file name "${id}.json"` });
        }
    }

    if (!Array.isArray(raw.versions) || raw.versions.length === 0) {
        errors.push({ file, message: "versions: expected a non-empty array" });
    } else {
        const seen = new Set();
        raw.versions.forEach((version, index) => {
            validateVersion(version, index, file, errors);
            if (isRecord(version) && isNonEmptyString(version.version)) {
                if (seen.has(version.version)) {
                    errors.push({ file, message: `versions[${index}].version: duplicate version ${version.version}` });
                }
                seen.add(version.version);
            }
        });
    }

    return errors.length === before ? raw : undefined;
}

/** Загружает и валидирует все исходники разом; проверяет коллизии id между файлами. */
function loadAll(errors) {
    const metas = [];
    const byLowerId = new Map();
    for (const file of listSourceFiles()) {
        const raw = readSource(file, errors);
        if (raw === undefined) continue;
        const meta = validateMeta(raw, file, errors);
        if (meta === undefined) continue;
        // Регистр в id значим (сверка с манифестом побайтная), но два файла,
        // различающиеся только регистром, — коллизия на macOS/Windows.
        const lower = meta.id.toLowerCase();
        const clash = byLowerId.get(lower);
        if (clash !== undefined) {
            errors.push({ file, message: `id collides with ${clash} (ids differing only in case are not allowed)` });
            continue;
        }
        byLowerId.set(lower, file);
        metas.push(meta);
    }
    // Кодпоинтная сортировка, не localeCompare: локаль раннера не должна влиять на вывод.
    metas.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return metas;
}

// --- иммутабельность -------------------------------------------------------

function gitShow(ref, file) {
    try {
        return execFileSync("git", ["show", `${ref}:${file}`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch {
        return undefined;
    }
}

function gitListSources(ref) {
    try {
        const out = execFileSync("git", ["ls-tree", "-r", "--name-only", ref, "--", SRC_DIR], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
        });
        return out.split("\n").filter((line) => line.endsWith(".json"));
    } catch (error) {
        throw new Error(`cannot list ${SRC_DIR} at ${ref}: ${error.message}`);
    }
}

/**
 * Опубликованная версия неизменна: клиенты уже запинили её sha256, а подмена
 * артефакта под тем же номером — ровно то, от чего пин и защищает.
 *
 * Сравниваются СЫРЫЕ записи версий, а не разобранные: разбор выбрасывает
 * неизвестные поля и замаскировал бы правку. База берётся из git, а не из
 * опубликованного дерева, — в ветке PR оно устаревшее и пропустило бы правку
 * версии, опубликованной после точки ветвления.
 */
function checkImmutability(base, allowRemovals, errors) {
    for (const file of gitListSources(base)) {
        const baseText = gitShow(base, file);
        if (baseText === undefined) continue;
        let baseMeta;
        try {
            baseMeta = JSON.parse(baseText);
        } catch {
            // База невалидна — сравнивать не с чем; текущий файл проверит обычная валидация.
            continue;
        }
        if (!isRecord(baseMeta) || !Array.isArray(baseMeta.versions)) continue;

        if (!fs.existsSync(file)) {
            if (!allowRemovals) {
                errors.push({ file, message: "extension file removed (use --allow-removals if intentional)" });
            }
            continue;
        }
        const headRaw = readSource(file, errors);
        if (headRaw === undefined || !isRecord(headRaw) || !Array.isArray(headRaw.versions)) continue;

        const headByVersion = new Map();
        for (const version of headRaw.versions) {
            if (isRecord(version) && isNonEmptyString(version.version)) headByVersion.set(version.version, version);
        }
        for (const baseVersion of baseMeta.versions) {
            if (!isRecord(baseVersion) || !isNonEmptyString(baseVersion.version)) continue;
            const head = headByVersion.get(baseVersion.version);
            if (head === undefined) {
                if (!allowRemovals) {
                    errors.push({
                        file,
                        message: `version ${baseVersion.version} removed (published versions are immutable)`,
                    });
                }
                continue;
            }
            if (canonicalJson(head) !== canonicalJson(baseVersion)) {
                errors.push({
                    file,
                    message: `version ${baseVersion.version} was modified (published versions are immutable; add a new version instead)`,
                });
            }
        }
    }
}

// --- скачивание артефактов -------------------------------------------------

/** Читает свой артефакт из рабочего дерева по пути из URL (`/artifacts/x.vsix` → `artifacts/x.vsix`). */
function readSelfArtifact(url, file, where, errors) {
    const local = decodeURIComponent(url.pathname).replace(/^\/+/, "");
    if (!fs.existsSync(local)) {
        errors.push({ file, message: `${where}: artifact is hosted here but missing from the repository: ${local}` });
        return undefined;
    }
    return fs.readFileSync(local);
}

async function fetchArtifact(url, file, where, errors) {
    let response;
    try {
        response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    } catch (error) {
        throw new Error(`${where}: cannot download ${url}: ${error.message}`);
    }
    if (!response.ok) {
        errors.push({ file, message: `${where}: download failed with HTTP ${response.status}: ${url}` });
        return undefined;
    }
    // Редирект мог увести за пределы списка — проверяем именно конечный адрес.
    const finalHost = new URL(response.url).host;
    if (!ARTIFACT_HOSTS.has(finalHost)) {
        errors.push({ file, message: `${where}: redirected to disallowed host "${finalHost}"` });
        return undefined;
    }
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.byteLength > MAX_ARTIFACT_BYTES) {
        errors.push({ file, message: `${where}: artifact is larger than ${MAX_ARTIFACT_BYTES} bytes` });
        return undefined;
    }
    return buffer;
}

/** Сверяет sha256 (и `size`, если заявлен) с тем, что реально лежит по URL. */
async function checkArtifacts(metas, publishedVersions, errors) {
    for (const meta of metas) {
        for (const [index, version] of meta.versions.entries()) {
            const key = `${meta.id}@${version.version}`;
            if (publishedVersions.has(key)) continue;
            const where = `versions[${index}] (${version.version})`;
            const file = path.posix.join(SRC_DIR, `${meta.id}.json`);
            const url = new URL(version.artifact.url);
            const buffer =
                url.host === SELF_HOST
                    ? readSelfArtifact(url, file, where, errors)
                    : await fetchArtifact(version.artifact.url, file, where, errors);
            if (buffer === undefined) continue;
            const actual = crypto.createHash("sha256").update(buffer).digest("hex");
            if (actual !== version.sha256) {
                errors.push({ file, message: `${where}: sha256 mismatch — declared ${version.sha256}, actual ${actual}` });
            }
            if (version.size !== undefined && version.size !== buffer.byteLength) {
                errors.push({ file, message: `${where}: size mismatch — declared ${version.size}, actual ${buffer.byteLength}` });
            }
        }
    }
}

/** Множество `id@version`, уже опубликованных в базе, — их скачивать заново незачем. */
function publishedVersionsAt(base) {
    const published = new Set();
    for (const file of gitListSources(base)) {
        const text = gitShow(base, file);
        if (text === undefined) continue;
        try {
            const meta = JSON.parse(text);
            if (!isRecord(meta) || !Array.isArray(meta.versions)) continue;
            for (const version of meta.versions) {
                if (isRecord(version) && isNonEmptyString(version.version)) published.add(`${meta.id}@${version.version}`);
            }
        } catch {
            continue;
        }
    }
    return published;
}

// --- сборка ----------------------------------------------------------------

/**
 * Максимум по semver, prerelease включительно — ровно та же политика, что в
 * `resolveCompatibleVersion.ts` у клиента. Расхождение политик между индексом и
 * тем, что реально поставится, хуже, чем prerelease в списке.
 */
function pickLatest(versions) {
    let best = versions[0];
    for (const candidate of versions) {
        if (semver.gt(candidate.version, best.version)) best = candidate;
    }
    return best;
}

function buildOutputs(metas) {
    const files = new Map();
    const entries = metas.map((meta) => {
        files.set(path.posix.join(OUT_DIR, "meta", `${meta.id}.json`), canonicalJson(canonicalMeta(meta)));
        const latest = pickLatest(meta.versions);
        return {
            id: meta.id,
            publisher: meta.publisher,
            name: meta.name,
            displayName: meta.displayName,
            description: meta.description,
            kind: meta.kind,
            latest: { version: latest.version, engines: canonicalEngines(latest.engines) },
        };
    });
    // generatedAt сознательно не пишем: он сделал бы каждую сборку диффом и убил
    // бы `--check` как дешёвую проверку «опубликованное соответствует исходникам».
    files.set(path.posix.join(OUT_DIR, "index.json"), canonicalJson({ schemaVersion: SCHEMA_VERSION, extensions: entries }));
    return files;
}

/** Что сейчас лежит в публикуемом каталоге — чтобы найти осиротевшее и сравнить при --check. */
function readPublished() {
    const existing = new Map();
    const walk = (dir) => {
        if (!fs.existsSync(dir)) return;
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.posix.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith(".json")) existing.set(full, fs.readFileSync(full, "utf8"));
        }
    };
    walk(OUT_DIR);
    return existing;
}

function runBuild(check) {
    const errors = [];
    const metas = loadAll(errors);
    if (errors.length > 0) {
        reportErrors(errors);
        console.error(`\n${errors.length} error(s); nothing was written.`);
        return 1;
    }

    const wanted = buildOutputs(metas);
    const existing = readPublished();

    if (check) {
        const diffs = [];
        for (const [file, content] of wanted) {
            if (existing.get(file) !== content) diffs.push(`${file}: out of date`);
        }
        for (const file of existing.keys()) {
            if (!wanted.has(file)) diffs.push(`${file}: stale (no matching source)`);
        }
        if (diffs.length > 0) {
            for (const line of diffs) console.error(line);
            console.error(`\n${OUT_DIR} does not match ${SRC_DIR}; run: node scripts/registry.mjs build`);
            return 1;
        }
        console.log(`${OUT_DIR} is up to date (${metas.length} extension(s)).`);
        return 0;
    }

    for (const [file, content] of wanted) {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        if (existing.get(file) !== content) fs.writeFileSync(file, content);
    }
    // Снятое расширение обязано исчезнуть из публикуемого вида, иначе оно останется
    // доступным для установки навсегда.
    for (const file of existing.keys()) {
        if (!wanted.has(file)) fs.rmSync(file);
    }
    console.log(`Built ${OUT_DIR}: ${metas.length} extension(s), ${wanted.size} file(s).`);
    return 0;
}

async function runValidate(base, doFetch, allowRemovals) {
    const errors = [];
    const metas = loadAll(errors);

    if (base !== undefined) {
        checkImmutability(base, allowRemovals, errors);
    }
    if (doFetch && errors.length === 0) {
        const published = base === undefined ? new Set() : publishedVersionsAt(base);
        await checkArtifacts(metas, published, errors);
    }

    if (errors.length > 0) {
        reportErrors(errors);
        console.error(`\n${errors.length} error(s).`);
        return 1;
    }
    console.log(`OK: ${metas.length} extension(s) valid${doFetch ? ", artifacts verified" : ""}.`);
    return 0;
}

// --- CLI -------------------------------------------------------------------

function optionValue(argv, name) {
    const index = argv.indexOf(name);
    if (index === -1) return undefined;
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
        throw new Error(`${name} requires a value`);
    }
    return value;
}

async function main() {
    const argv = process.argv.slice(2);
    const command = argv[0];

    if (command === "validate") {
        return await runValidate(optionValue(argv, "--base"), argv.includes("--fetch"), argv.includes("--allow-removals"));
    }
    if (command === "build") {
        return runBuild(argv.includes("--check"));
    }
    console.error("usage: registry.mjs validate [--base <ref>] [--fetch] [--allow-removals] | build [--check]");
    return 2;
}

try {
    process.exitCode = await main();
} catch (error) {
    // Отличаем сбой инструмента (сеть, git, аргументы) от невалидных данных: в CI
    // первое чинят мейнтейнеры, второе — автор PR.
    console.error(`registry.mjs: ${error.message}`);
    process.exitCode = 2;
}
