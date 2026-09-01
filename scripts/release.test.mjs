import test from "node:test";
import assert from "node:assert/strict";
import { publishRelease, verifyAssets, validateExecutable, digest } from "./release.mjs";

const sha = "a".repeat(40);
const artifacts = ["bastionctl.exe", "bastionctl-2.2.0-source.tar.gz", "SHA256SUMS"].map((name) => ({ name, data: Buffer.from(name) }));
const asset = (file) => ({ name: file.name, size: file.data.length, digest: digest(file.data), state: "uploaded" });
const options = { repository: "v1waa/bastionctl-vi", sha, version: "2.2.0", notes: "# bastionctl 2.2.0\n\nNotes", artifacts };

function fixture({ existing = null, ref = null, moved = false } = {}) {
  const writes = [];
  let release = existing;
  return { writes, request: async (method, path, body) => {
    if (method !== "GET") writes.push({ method, path, body });
    if (path === "/git/ref/heads/main") return { object: { sha: moved ? "b".repeat(40) : sha } };
    if (path === "/git/ref/tags/v2.2.0") return ref || (release && !release.draft ? { object: { type: "commit", sha } } : null);
    if (method === "GET" && path === "/releases/tags/v2.2.0") return release;
    if (method === "POST" && path === "/releases") {
      release = { ...body, id: 1, assets: [], upload_url: "https://uploads.github.com/repos/v1waa/bastionctl-vi/releases/1/assets{?name,label}", html_url: "https://github.com/v1waa/bastionctl-vi/releases/tag/v2.2.0" };
      return release;
    }
    if (method === "POST" && path.startsWith("https://uploads.github.com/")) {
      const name = new URL(path).searchParams.get("name");
      const uploaded = asset(artifacts.find((file) => file.name === name));
      release.assets.push(uploaded);
      return uploaded;
    }
    if (method === "PATCH" && path === "/releases/1") { release = { ...release, ...body }; return release; }
    if (method === "GET" && path === "/releases/1") return release;
    throw new Error(`Unexpected test request: ${method} ${path}`);
  } };
}

test("release stays a draft until all three assets have verified digests", async () => {
  const mock = fixture();
  assert.match(await publishRelease({ ...options, request: mock.request }), /v2\.2\.0$/);
  assert.equal(mock.writes[0].body.draft, true);
  assert.equal(mock.writes.filter((call) => call.path.startsWith("https://uploads.github.com/")).length, 3);
  assert.deepEqual(mock.writes.at(-1).body, { draft: false, make_latest: "true" });
});

test("moved main and existing tag on another commit produce no writes", async () => {
  for (const setup of [{ moved: true }, { ref: { object: { type: "commit", sha: "b".repeat(40) } } }]) {
    const mock = fixture(setup);
    await assert.rejects(publishRelease({ ...options, request: mock.request }));
    assert.equal(mock.writes.length, 0);
  }
});

test("verified published releases are never overwritten", async () => {
  const mock = fixture({ existing: { draft: false, assets: artifacts.map(asset), html_url: "existing" } });
  assert.equal(await publishRelease({ ...options, request: mock.request }), "existing");
  assert.equal(mock.writes.length, 0);
});

test("foreign drafts, wrong hashes, missing files and non-production EXEs are rejected", async () => {
  const mock = fixture({ existing: { draft: true, target_commitish: sha, body: "manual draft" } });
  await assert.rejects(publishRelease({ ...options, request: mock.request }), /Existing draft/);
  assert.equal(mock.writes.length, 0);
  assert.throws(() => verifyAssets([], artifacts), /asset set/);
  const bad = artifacts.map(asset);
  bad[0].digest = "sha256:wrong";
  assert.throws(() => verifyAssets(bad, artifacts), /bastionctl.exe/);
  assert.throws(() => validateExecutable(Buffer.from("MZstub")), /production Windows/);
});

test("wrong repository and version fail before any request", async () => {
  let calls = 0;
  const request = async () => { calls++; };
  await assert.rejects(publishRelease({ ...options, repository: "other/repo", request }), /Invalid release target/);
  await assert.rejects(publishRelease({ ...options, version: "../../main", request }), /Invalid release target/);
  assert.equal(calls, 0);
});

test("an upload with an incorrect server-side hash cannot publish the draft", async () => {
  const mock = fixture();
  const request = async (...args) => {
    const result = await mock.request(...args);
    if (args[1].startsWith("https://uploads.github.com/")) result.digest = "sha256:corrupt";
    return result;
  };
  await assert.rejects(publishRelease({ ...options, request }), /asset verification failed/);
  assert.equal(mock.writes.some((call) => call.method === "PATCH"), false);
});
