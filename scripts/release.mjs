import { createHash } from "node:crypto";
import { readFile, appendFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const marker = "<!-- bastionctl release workflow -->";
export const digest = (data) => `sha256:${createHash("sha256").update(data).digest("hex")}`;

export function verifyAssets(remote, artifacts) {
  if (remote.length !== artifacts.length) throw new Error("Unexpected release asset set");
  for (const artifact of artifacts) {
    const matches = remote.filter((asset) => asset.name === artifact.name);
    if (matches.length !== 1 || matches[0].state !== "uploaded" ||
        matches[0].size !== artifact.data.length || matches[0].digest !== digest(artifact.data)) {
      throw new Error(`Release asset verification failed: ${artifact.name}`);
    }
  }
}

export function validateExecutable(data) {
  if (data.length < 20_000_000 || data.toString("ascii", 0, 2) !== "MZ") {
    throw new Error("Expected a production Windows EXE with embedded Ubuntu payloads");
  }
  const pe = data.readUInt32LE(0x3c);
  if (pe + 96 > data.length || data.readUInt32LE(pe) !== 0x4550 ||
      data.readUInt16LE(pe + 4) !== 0x8664 || data.readUInt16LE(pe + 24) !== 0x20b ||
      data.readUInt16LE(pe + 24 + 68) !== 2) {
    throw new Error("Expected an amd64 PE32+ GUI executable");
  }
}

export async function publishRelease({ repository, sha, version, notes, artifacts, request }) {
  if (repository !== "v1waa/bastionctl-vi" || !/^[a-f0-9]{40}$/.test(sha) ||
      !/^\d+\.\d+\.\d+$/.test(version)) throw new Error("Invalid release target");
  if (!notes.startsWith(`# bastionctl ${version}\n`)) throw new Error("Release notes version mismatch");
  const names = ["bastionctl.exe", `bastionctl-${version}-source.tar.gz`, "SHA256SUMS"];
  if (JSON.stringify(artifacts.map((item) => item.name)) !== JSON.stringify(names)) {
    throw new Error("Invalid local artifact set");
  }
  const tag = `v${version}`;
  const assertMain = async () => {
    const main = await request("GET", "/git/ref/heads/main");
    if (main.object?.sha !== sha) throw new Error("main moved; refusing to publish a stale build");
  };
  const resolveTag = async (ref) => {
    let object = ref?.object;
    for (let depth = 0; object?.type === "tag" && depth < 5; depth++) {
      object = (await request("GET", `/git/tags/${object.sha}`)).object;
    }
    return object;
  };
  await assertMain();
  const ref = await request("GET", `/git/ref/tags/${tag}`, null, true);
  const tagged = await resolveTag(ref);
  if (tagged && (tagged.type !== "commit" || tagged.sha !== sha)) {
    throw new Error(`${tag} already points to another commit; increase VERSION`);
  }
  let release = await request("GET", `/releases/tags/${tag}`, null, true);
  if (release && !release.draft) {
    if (!tagged) throw new Error("Published release has no verified tag");
    verifyAssets(release.assets || [], artifacts);
    return release.html_url;
  }
  if (release && (release.target_commitish !== sha || !release.body?.includes(marker))) {
    throw new Error("Existing draft was not created by this workflow for this commit");
  }
  if (!release) {
    release = await request("POST", "/releases", {
      tag_name: tag, target_commitish: sha, name: `bastionctl ${version}`,
      body: `${notes}\n${marker}\n\nCommit: ${sha}\n`, draft: true, prerelease: false
    });
  }
  const upload = new URL(release.upload_url.replace(/\{.*$/, ""));
  if (upload.origin !== "https://uploads.github.com" ||
      upload.pathname !== `/repos/${repository}/releases/${release.id}/assets` ||
      upload.username || upload.password) throw new Error("Unexpected upload destination");
  for (const artifact of artifacts) {
    const existing = (release.assets || []).filter((asset) => asset.name === artifact.name);
    if (existing.length) {
      verifyAssets(existing, [artifact]);
      continue;
    }
    upload.searchParams.set("name", artifact.name);
    const result = await request("POST", upload.href, artifact.data);
    verifyAssets([result], [artifact]);
  }
  release = await request("GET", `/releases/${release.id}`);
  verifyAssets(release.assets || [], artifacts);
  await assertMain();
  const published = await request("PATCH", `/releases/${release.id}`, { draft: false, make_latest: "true" });
  if (published.draft) throw new Error("Release is still a draft");
  const finalRef = await request("GET", `/git/ref/tags/${tag}`);
  const finalTarget = await resolveTag(finalRef);
  if (finalTarget?.type !== "commit" || finalTarget.sha !== sha) {
    throw new Error("Published tag verification failed");
  }
  return published.html_url;
}

async function main() {
  const { GITHUB_TOKEN: token, GITHUB_REPOSITORY: repository, GITHUB_SHA: sha } = process.env;
  if (!token || process.env.GITHUB_ACTIONS !== "true" || process.env.GITHUB_REF !== "refs/heads/main") {
    throw new Error("Publishing is only allowed in the main-branch GitHub Actions job");
  }
  const version = (await readFile("VERSION", "utf8")).trim();
  const notes = await readFile("RELEASE_NOTES.md", "utf8");
  const names = ["bastionctl.exe", `bastionctl-${version}-source.tar.gz`, "SHA256SUMS"];
  const artifacts = await Promise.all(names.map(async (name) => ({ name, data: await readFile(resolve("dist", name)) })));
  validateExecutable(artifacts[0].data);
  const sums = artifacts.slice(0, 2).map((file) => `${digest(file.data).slice(7)}  ${file.name}\n`).join("");
  if (artifacts[2].data.toString("utf8") !== sums) throw new Error("SHA256SUMS does not match local artifacts");
  const request = async (method, path, body = null, optional = false) => {
    const url = path.startsWith("https://") ? path : `https://api.github.com/repos/${repository}${path}`;
    const response = await fetch(url, {
      method, redirect: "error", signal: AbortSignal.timeout(180_000),
      headers: {
        Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": Buffer.isBuffer(body) ? "application/octet-stream" : "application/json"
      },
      body: body === null ? undefined : Buffer.isBuffer(body) ? body : JSON.stringify(body)
    });
    if (optional && response.status === 404) return null;
    if (!response.ok) throw new Error(`GitHub ${method} ${new URL(url).pathname}: HTTP ${response.status}`);
    return response.json();
  };
  const url = await publishRelease({ repository, sha, version, notes, artifacts, request });
  console.log(`Published and verified: ${url}`);
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `Release: ${url}\n\nCommit: ${sha}\n\n\`\`\`text\n${sums}\`\`\`\n`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
