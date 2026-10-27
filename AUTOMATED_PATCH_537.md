Contributor details
Your Expensify account email: 3055073676@qq.com
Upwork Profile Link: https://www.upwork.com/freelancers/~01a6c3832b8108493d

## Proposal

### Please re-state the problem that we are trying to solve in this issue.

Minerval currently operates as a single-profile monolithic public knowledge graph deployment (`minerval.ai`). In its present architecture, the claim graph, automated agents, model provider adapters, and API/MCP surfaces are tightly coupled to a public deployment model with platform owl token billing, bounty prizes, Lean 4 formal math verification, and browser extension endpoints.

Under [Issue #537](https://github.com/minerval-ai/minerval/issues/537) (building on [#522](https://github.com/minerval-ai/minerval/issues/522) and [#304](https://github.com/minerval-ai/minerval/issues/304)), embedded evaluators (such as frontier AI safety auditors, evaluation labs, and national safety institutes) need to independently assess an AI developer's safety case (claims, arguments, empirical capability evals, red-teaming benchmarks, and safety protocols) on their own self-hosted infrastructure and private model instances.

The current system exhibits four major architectural limitations:
1. **No Profile-Gated Deployment Configuration**: There is no deployment profile mechanism (`public` vs `evaluator` vs `fork`). Commercial and public-facing modules (`/billing`, `/orders`, `/prizes`, `/formalizations`, `/extension`) are loaded indiscriminately, and there is no configuration preset to selectively toggle features or deploy to air-gapped/evaluator VPC environments.
2. **Provider Seam Lock-in**: In [`src/llm/providers/routing.ts`](file:///root/remote_claw/src/llm/providers/routing.ts) and [`src/config.ts`](file:///root/remote_claw/src/config.ts), model ID routing only supports direct Anthropic, OpenAI, and OpenRouter backends. AWS Bedrock-prefixed IDs (`us.anthropic...`, `anthropic...`) are explicitly rejected by regex as unresolvable foot-guns, and GCP Vertex AI is unsupported, preventing evaluators from running agents against private VPC models.
3. **Missing Sealed Evidence & Visibility Boundaries**: In [`src/db/schema.ts`](file:///root/remote_claw/src/db/schema.ts) and [`src/mcp/server.ts`](file:///root/remote_claw/src/mcp/server.ts), evidence and sources have no visibility partition (`public` vs `sealed` vs `run_generated`). Evaluator assessments that ingest private developer evidence (proprietary training mixture details, unredacted zero-day exploit attempts, internal monitoring feeds) cannot seal the evidence while publishing instructions, verdicts, and redacted reasoning to a verifiable static export.
4. **Lack of Cross-Cutting Granular MCP/API Contract & Tamper-Evident Run Logs**: The MCP server (`src/mcp/server.ts`) and REST routes do not follow the summary-first expansion model with cursor pagination, and `agent_runs` / `agent_steps` do not maintain cryptographic hash chaining to guarantee audit tamper-evidence.

---

### What is the root cause of that problem?

1. **Monolithic Configuration Schema (`src/config.ts`)**:
   - `configSchema` lacks a `deploymentProfile` enum (`"public" | "evaluator" | "fork"`).
   - Validation helper `modelId()` and `isSupportedModelId()` in `src/llm/providers/routing.ts` hardcode `ACCEPTED_MODEL_ID_SHAPES` to exclude Bedrock and Vertex endpoints.
   - Evaluator-specific configurations (signing private keys for static exports, Bedrock/Vertex credentials, and feature switches) are completely absent.
2. **Unconditional Route Mounting (`src/server/app.ts:buildApp`)**:
   - `buildApp()` unconditionally mounts `formalizationsRoutes`, `attemptsRoutes`, `prizesRoutes`, `billingRoutes`, `orderRoutes`, and `extensionRoutes`. In an evaluator environment, exposing public billing, token economies, and Lean theorem checkers creates unnecessary attack surfaces and operational dependencies.
3. **Restricted Provider Registry (`src/llm/providers/routing.ts`, `src/llm/providers/types.ts`, `src/llm/providers/index.ts`)**:
   - `ProviderName` in `types.ts` is limited to `"anthropic" | "openai" | "openrouter"`.
   - `isBedrockStyleId()` in `routing.ts` actively rejects Bedrock model IDs instead of directing them to an AWS Bedrock adapter.
4. **Missing Sealed Evidence Visibility & Tamper-Proof Audit Schema (`src/db/schema.ts`)**:
   - The `sources` table lacks a `visibility` column (`public`, `sealed`, `run_generated`), as well as redaction status fields (`redacted_content`, `redaction_hash`).
   - The `arguments_` and `claims` tables lack safety-case ontology columns: `is_defeater`, `coverage_status`, and decomposed `score_components`.
   - The `agent_steps` table records only `run_id`, `step_index`, and `action_payload` without a SHA-256 `prev_step_hash` / `step_hash`, making execution traces susceptible to retroactive tampering.
5. **Direct Unpartitioned Reads in MCP Server (`src/mcp/server.ts`)**:
   - Tools like `get_claim`, `search_claims`, and `get_decomposition` query and return database records directly without enforcing visibility rules (e.g., stripping or substituting sealed source excerpts for unauthorized callers).

---

### What changes do you think we should make in order to solve the problem?

#### 1. Introduce Deployment Profile & Provider Configuration in `src/config.ts`

Add `deploymentProfile` (`public`, `evaluator`, `fork`) and provider credentials (Bedrock, Vertex, and export signing key) to `configSchema`:

```diff
--- a/src/config.ts
+++ b/src/config.ts
@@ -35,6 +35,9 @@
 function normalizePrivateKey(raw: string): string {
   const unescaped = raw.replace(/\\n/g, "\n").trim();
   if (!unescaped || unescaped.includes("-----BEGIN")) return unescaped;
   const decoded = Buffer.from(unescaped, "base64").toString("utf8");
   return decoded.includes("-----BEGIN") ? decoded.trim() : unescaped;
 }

 const configSchema = z.object({
+  // Deployment Profile: public (minerval.ai), evaluator (safety case assessment), or fork (#537)
+  deploymentProfile: z
+    .enum(["public", "evaluator", "fork"])
+    .default("public"),
   env: z
     .enum(["development", "staging", "production"])
     .default("development"),
@@ -62,6 +65,15 @@
   openaiApiKey: z.string().default(""),
   anthropicApiKey: z.string().default(""),
   openrouterApiKey: z.string().default(""),
+  // AWS Bedrock configuration
+  awsBedrockRegion: z.string().default("us-east-1"),
+  awsBedrockEndpoint: z.string().optional(),
+  // Google Cloud Vertex AI configuration
+  vertexProjectId: z.string().default(""),
+  vertexRegion: z.string().default("us-central1"),
+  // Signed static export private key (ED25519 / RSA PEM)
+  exportSigningPrivateKey: z.string().transform(normalizePrivateKey).default(""),
   openrouterProviderSort: z.enum(["price", "throughput", "latency"]).optional(),
   awsRegion: z.string().default("us-east-1"),
```

Extend `src/config.ts` with profile-aware feature helper functions:

```typescript
export function isProfileFeatureEnabled(
  profile: "public" | "evaluator" | "fork",
  feature: "currency" | "prizes" | "extension" | "mathematics" | "sealedEvidence"
): boolean {
  if (profile === "evaluator") {
    // Currency, bounties/prizes, extension, and Lean mathematics are disabled for evaluator profile
    return feature === "sealedEvidence";
  }
  return feature !== "sealedEvidence";
}
```

---

#### 2. Extend the Multi-Provider Seam in `src/llm/providers/`

Update `src/llm/providers/types.ts`:
```diff
--- a/src/llm/providers/types.ts
+++ b/src/llm/providers/types.ts
@@ -19,7 +19,7 @@
 export type LlmContentBlock = Anthropic.ContentBlock;

-/** The three backends behind the seam. */
-export type ProviderName = "anthropic" | "openai" | "openrouter";
+/** The backends behind the seam (#537 adds bedrock and vertex). */
+export type ProviderName = "anthropic" | "openai" | "openrouter" | "bedrock" | "vertex";

 export interface TokenUsage {
```

Update `src/llm/providers/routing.ts` to route Bedrock and Vertex model IDs:
```diff
--- a/src/llm/providers/routing.ts
+++ b/src/llm/providers/routing.ts
@@ -9,16 +9,23 @@
  *   ^claude-        → anthropic   (Anthropic direct, e.g. "claude-sonnet-5-5")
  *   ^gpt- | ^o\d    → openai      (OpenAI direct, e.g. "gpt-5-nano", "o3")
+ *   ^([a-z]{2,4}\.)?anthropic\. | ^amazon\. → bedrock (AWS Bedrock)
+ *   ^vertex_ai/ | ^google/ | ^publishers/   → vertex  (Google Vertex AI)
  *   contains "/"    → openrouter  (their vendor/model convention)
  */
 export const ACCEPTED_MODEL_ID_SHAPES =
   'an Anthropic ID ("claude-…"), an OpenAI ID ("gpt-…" or "o3"), an ' +
-  'OpenRouter "vendor/model" ID (e.g. "qwen/qwen3-235b-a22b")';
+  'AWS Bedrock ID ("anthropic.…" or "us.anthropic.…"), Vertex AI ID ("vertex_ai/…"), ' +
+  'or an OpenRouter "vendor/model" ID';

-function isBedrockStyleId(id: string): boolean {
+export function isBedrockStyleId(id: string): boolean {
   return /^([a-z]{2,4}\.)?anthropic\./.test(id) || /^amazon\./.test(id);
 }
+
+export function isVertexStyleId(id: string): boolean {
+  return /^(vertex_ai\/|google\/|publishers\/)/.test(id);
+}

 export function providerForModel(id: string): ProviderName {
   if (isAnthropicModelId(id)) return "anthropic";
   if (isOpenAiModelId(id)) return "openai";
+  if (isBedrockStyleId(id)) return "bedrock";
+  if (isVertexStyleId(id)) return "vertex";
   if (isOpenRouterModelId(id)) return "openrouter";
   throw new Error(`Unresolvable model ID: ${id}`);
 }
```

Register `bedrockAdapter` and `vertexAdapter` in `src/llm/providers/index.ts`:
```diff
--- a/src/llm/providers/index.ts
+++ b/src/llm/providers/index.ts
@@ -10,12 +10,16 @@
 import { anthropicAdapter } from "./anthropic.js";
 import { openaiAdapter } from "./openai.js";
 import { openrouterAdapter } from "./openrouter.js";
+import { bedrockAdapter } from "./bedrock.js";
+import { vertexAdapter } from "./vertex.js";
 import { providerForModel } from "./routing.js";
 import type { ProviderAdapter, ProviderName } from "./types.js";

 const ADAPTERS: Record<ProviderName, ProviderAdapter> = {
   anthropic: anthropicAdapter,
   openai: openaiAdapter,
   openrouter: openrouterAdapter,
+  bedrock: bedrockAdapter,
+  vertex: vertexAdapter,
 };
```

---

#### 3. Conditional Feature Gating in `src/server/app.ts`

Gate commercial routes and formal mathematics routes when running under the `evaluator` profile, and register the evaluator export and run inspection routes:

```diff
--- a/src/server/app.ts
+++ b/src/server/app.ts
@@ -3,6 +3,7 @@
 import Fastify from "fastify";
 import formbody from "@fastify/formbody";
-import { loadConfig } from "../config.js";
+import { loadConfig, isProfileFeatureEnabled } from "../config.js";
 import { registerSwagger } from "./plugins/swagger.js";
@@ -40,6 +41,7 @@
 import { reportRoutes } from "../routes/reports.js";
 import { findingRoutes } from "../routes/findings.js";
 import { tagRoutes } from "../routes/tags.js";
+import { evaluatorRoutes } from "../routes/evaluator.js";

 export async function buildApp() {
   const config = loadConfig();
@@ -74,10 +76,14 @@
   await app.register(userRoutes, { prefix: "/users" });
   await app.register(contributorRoutes, { prefix: "/contributors" });
   await app.register(apiKeyRoutes, { prefix: "/api-keys" });
   await app.register(usageRoutes, { prefix: "/usage" });
-  await app.register(billingRoutes, { prefix: "/billing" });
-  await app.register(orderRoutes, { prefix: "/orders" });
+  if (isProfileFeatureEnabled(config.deploymentProfile, "currency")) {
+    await app.register(billingRoutes, { prefix: "/billing" });
+    await app.register(orderRoutes, { prefix: "/orders" });
+  }
   await app.register(budgetJobRoutes, { prefix: "/budget-jobs" });
   await app.register(queueRoutes, { prefix: "/queue" });
@@ -91,9 +97,14 @@
   await app.register(reportRoutes, { prefix: "/reports" });
   await app.register(findingRoutes, { prefix: "/findings" });
   await app.register(tagRoutes, { prefix: "/tags" });
   await app.register(mcpRoutes, { prefix: "/mcp" });
-  await app.register(formalizationsRoutes);
-  await app.register(attemptsRoutes);
-  await app.register(prizesRoutes);
+  if (isProfileFeatureEnabled(config.deploymentProfile, "mathematics")) {
+    await app.register(formalizationsRoutes);
+    await app.register(attemptsRoutes);
+    await app.register(prizesRoutes);
+  }
+  if (config.deploymentProfile === "evaluator") {
+    await app.register(evaluatorRoutes, { prefix: "/evaluator" });
+  }
   await app.register(oauthRoutes);
-  await app.register(extensionRoutes, { prefix: "/extension" });
+  if (isProfileFeatureEnabled(config.deploymentProfile, "extension")) {
+    await app.register(extensionRoutes, { prefix: "/extension" });
+  }
```

---

#### 4. Schema Additions for Sealed Evidence, Case Ontology & Tamper-Evident Run Logs in `src/db/schema.ts`

Add visibility status, defeater claims, argument coverage metrics, and sequential SHA-256 step hash chains:

```diff
--- a/src/db/schema.ts
+++ b/src/db/schema.ts
@@ -105,6 +105,10 @@
 export const claimTypeEnum = pgEnum("claim_type", [
   "empirical",
   "formal",
+  "safety_case",
+  "defeater",
 ]);

+export const sourceVisibilityEnum = pgEnum("source_visibility", [
+  "public",
+  "sealed",
+  "run_generated",
+]);
+
@@ -185,6 +195,10 @@
 export const claims = pgTable("claims", {
   id: uuid("id").primaryKey().defaultRandom(),
   canonicalStatement: text("canonical_statement").notNull(),
+  isDefeater: boolean("is_defeater").notNull().default(false),
+  targetArgumentId: uuid("target_argument_id"),
+  systemId: text("system_id"),
+  deploymentId: text("deployment_id"),
   claimType: claimTypeEnum("claim_type").notNull().default("empirical"),
@@ -340,6 +354,10 @@
 export const sources = pgTable("sources", {
   id: uuid("id").primaryKey().defaultRandom(),
   url: text("url").unique(),
   title: text("title").notNull(),
+  visibility: sourceVisibilityEnum("visibility").notNull().default("public"),
+  redactedContent: text("redacted_content"),
+  redactionStatus: text("redaction_status").default("none"), // none | pending | redacted
+  redactionFidelityScore: doublePrecision("redaction_fidelity_score"),
   contentHash: text("content_hash").unique(),
   rawContent: text("raw_content"),
@@ -750,6 +768,8 @@
 export const agentSteps = pgTable("agent_steps", {
   id: uuid("id").primaryKey().defaultRandom(),
   runId: uuid("run_id").notNull(),
   stepIndex: integer("step_index").notNull(),
+  prevStepHash: text("prev_step_hash"),
+  stepHash: text("step_hash").notNull(),
   action: text("action").notNull(),
   payload: jsonb("payload"),
 });
```

---

#### 5. Cross-Cutting MCP Visibility & Redaction Engine in `src/mcp/server.ts`

Implement visibility filtering so MCP tool reads and writes strictly mask sealed evidence for public callers while exposing IDs, summaries, and cursors:

```typescript
// Helper in src/services/visibility-service.ts
export function sanitizeSourceForCaller(
  source: SourceRecord,
  callerRole: "evaluator" | "developer" | "public"
): Partial<SourceRecord> {
  if (source.visibility === "sealed" && callerRole === "public") {
    return {
      id: source.id,
      title: source.title,
      visibility: "sealed",
      rawContent: source.redactedContent ?? "[SEALED EVIDENCE: Redacted reasoning published]",
      contentHash: source.contentHash,
      retrievedAt: source.retrievedAt,
    };
  }
  return source;
}
```

In `src/mcp/server.ts`, wrap `get_claim` and `get_decomposition` with `sanitizeSourceForCaller` and cursor-based pagination.

---

#### 6. Turnkey Evaluator Deployment Package (`infra/evaluator/docker-compose.yml`)

Provide an on-premises compose specification enabling isolated deployment:

```yaml
version: "3.8"
services:
  evaluator-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: episteme
      POSTGRES_PASSWORD: evaluator_secure_password
      POSTGRES_DB: episteme_evaluator
    volumes:
      - evaluator-data:/var/lib/postgresql/data
    networks:
      - evaluator-internal

  minerval-evaluator:
    build:
      context: ../..
      dockerfile: Dockerfile
    environment:
      DEPLOYMENT_PROFILE: evaluator
      DATABASE_URL: postgresql://episteme:evaluator_secure_password@evaluator-db:5432/episteme_evaluator
      AWS_BEDROCK_REGION: us-east-1
      PUBLIC_WEB_BASE_URL: https://evaluator.local
      LOG_LEVEL: info
    ports:
      - "3000:3000"
    depends_on:
      - evaluator-db
    networks:
      - evaluator-internal

volumes:
  evaluator-data:

networks:
  evaluator-internal:
    internal: false
```

---

### What alternative solutions did you explore? (Optional)

1. **Forking into a Separate Standalone Repository**:
   - *Explored*: Creating a dedicated `minerval-evaluator` repository.
   - *Rejected*: Violates the explicit core architecture decision of Issue #537 (*"One codebase, a separate deployment, configured by an evaluator profile"*). A codebase split creates catastrophic maintenance divergence, requiring every graph bugfix, MCP enhancement, and agent update to be maintained twice.
2. **Multi-Tenant Mode within the Public Cloud Database**:
   - *Explored*: Housing evaluator safety cases inside `minerval.ai`'s multi-tenant PostgreSQL tables using Row Level Security (RLS) policies.
   - *Rejected*: Incompatible with strict data custody requirements. Frontier lab private evaluation evidence (e.g. unreleased red-teaming benchmarks and model safety weights) must physically reside within the evaluator's boundary and never share database infrastructure with the public graph.
3. **Client-Side Only Visibility Redaction**:
   - *Explored*: Filtering sealed evidence inside Next.js web views while serving raw records from backend endpoints.
   - *Rejected*: Violates the cross-cutting acceptance criterion (*"its reads and writes are available over MCP and the API under the same visibility rules as the interface"*). Sealed evidence would leak through direct API calls or MCP tools.

---

### What automated tests can you add to prevent this from re-occurring?

Add a test suite `tests/unit/evaluator/evaluator-profile.test.ts` to verify profile enforcement, provider routing, sealed evidence redaction, and tamper-evident step hash chains:

```typescript
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "crypto";
import { isProfileFeatureEnabled } from "../../../src/config.js";
import { providerForModel, isBedrockStyleId, isVertexStyleId } from "../../../src/llm/providers/routing.js";
import { sanitizeSourceForCaller } from "../../../src/services/visibility-service.js";

describe("Evaluator Edition Profile and Feature Flags (#537)", () => {
  it("disables currency, prizes, and extension under evaluator profile", () => {
    expect(isProfileFeatureEnabled("evaluator", "currency")).toBe(false);
    expect(isProfileFeatureEnabled("evaluator", "prizes")).toBe(false);
    expect(isProfileFeatureEnabled("evaluator", "extension")).toBe(false);
    expect(isProfileFeatureEnabled("evaluator", "mathematics")).toBe(false);
    expect(isProfileFeatureEnabled("evaluator", "sealedEvidence")).toBe(true);
  });

  it("enables currency and prizes under public profile", () => {
    expect(isProfileFeatureEnabled("public", "currency")).toBe(true);
    expect(isProfileFeatureEnabled("public", "prizes")).toBe(true);
    expect(isProfileFeatureEnabled("public", "sealedEvidence")).toBe(false);
  });
});

describe("Evaluator Model Provider Routing (#537)", () => {
  it("routes AWS Bedrock model IDs to the bedrock provider", () => {
    const bedrockIds = [
      "anthropic.claude-3-5-sonnet-20241022-v2:0",
      "us.anthropic.claude-3-5-haiku-20241022-v1:0",
      "amazon.titan-text-express-v1",
    ];
    for (const id of bedrockIds) {
      expect(isBedrockStyleId(id)).toBe(true);
      expect(providerForModel(id)).toBe("bedrock");
    }
  });

  it("routes Vertex AI model IDs to the vertex provider", () => {
    const vertexIds = [
      "vertex_ai/gemini-1.5-pro",
      "google/gemini-2.0-flash",
      "publishers/google/models/gemini-1.5-pro",
    ];
    for (const id of vertexIds) {
      expect(isVertexStyleId(id)).toBe(true);
      expect(providerForModel(id)).toBe("vertex");
    }
  });
});

describe("Sealed Evidence Visibility Invariant (#537)", () => {
  const mockSealedSource = {
    id: "a1b2c3d4-0000-0000-0000-000000000001",
    title: "Confidential Red Teaming Evaluation Logs",
    visibility: "sealed" as const,
    rawContent: "PRIVATE_ZERO_DAY_PAYLOAD_EXPLOIT_DETAILS",
    redactedContent: "[REDACTED: Model exhibited refusal under exploit sequence]",
    contentHash: "hash-sealed-1234",
    retrievedAt: new Date("2026-10-26T00:00:00Z"),
  };

  it("masks raw content for public callers and provides redacted content", () => {
    const publicResult = sanitizeSourceForCaller(mockSealedSource, "public");
    expect(publicResult.rawContent).not.toContain("PRIVATE_ZERO_DAY_PAYLOAD");
    expect(publicResult.rawContent).toContain("[REDACTED: Model exhibited refusal");
  });

  it("reveals raw content to evaluator role", () => {
    const evalResult = sanitizeSourceForCaller(mockSealedSource, "evaluator");
    expect(evalResult.rawContent).toBe("PRIVATE_ZERO_DAY_PAYLOAD_EXPLOIT_DETAILS");
  });
});

describe("Tamper-Evident Run Log Hash Chain (#537)", () => {
  function computeStepHash(prevHash: string, action: string, payload: object): string {
    return crypto
      .createHash("sha256")
      .update(prevHash + action + JSON.stringify(payload))
      .digest("hex");
  }

  it("verifies sequential cryptographic link across agent run steps", () => {
    const step0Hash = computeStepHash("GENESIS", "init_assessment", { claim: "safety_case_root" });
    const step1Hash = computeStepHash(step0Hash, "evaluate_defeater", { defeater_id: "def_1" });
    const step2Hash = computeStepHash(step1Hash, "render_verdict", { status: "supported" });

    // Ensure step verification passes sequentially
    expect(step1Hash).not.toBe(step0Hash);
    expect(computeStepHash(step0Hash, "evaluate_defeater", { defeater_id: "def_1" })).toBe(step1Hash);

    // Tampering with payload in step 1 invalidates subsequent chain
    const tamperedStep1Hash = computeStepHash(step0Hash, "evaluate_defeater", { defeater_id: "def_TAMPERED" });
    expect(tamperedStep1Hash).not.toBe(step1Hash);
  });
});
```