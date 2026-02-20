# Security Code Review: aws-elasticbeanstalk-deploy

**Review Date:** 2026-02-20
**Scope:** Full source code, CI/CD workflows, configuration files, and example workflows
**Reviewed Files:** `src/*.ts`, `.github/workflows/*.yml`, `examples/*.yml`, `action.yml`, `package.json`

---

## Executive Summary

This GitHub Action deploys applications to AWS Elastic Beanstalk with automatic version management, environment creation, health monitoring, and retry logic. Overall, the codebase follows reasonable security practices for a GitHub Action. However, several findings of varying severity were identified.

| Severity | Count |
|----------|-------|
| High     | 2     |
| Medium   | 4     |
| Low      | 4     |
| Info     | 3     |

---

## High Severity

### H1: Path Traversal via `deployment-package-path` Input

**File:** `src/deploymentpackage.ts:17-35`, `src/aws-operations.ts:301-302`

**Description:** The `deployment-package-path` input is trimmed in `validations.ts:119` but never sanitized against path traversal. While `fs.existsSync()` and `fs.statSync()` verify the file exists and is a file, there is no validation that the path stays within the expected workspace directory (`GITHUB_WORKSPACE`). A malicious workflow author or a compromised upstream action that sets this input could point it to arbitrary files on the runner filesystem (e.g., `/etc/shadow`, credential files, or other workflow artifacts).

Additionally, the S3 key is constructed using the original file extension from the user-controlled path (`src/aws-operations.ts:301-302`):
```typescript
const packageExtension = path.extname(packagePath);
const key = `${applicationName}/${versionLabel}${packageExtension}`;
```
This allows an attacker to influence the S3 object key extension, though the impact is limited.

**Recommendation:**
- Validate that `packagePath` resolves to a location within `GITHUB_WORKSPACE` using `path.resolve()` and checking the prefix.
- Sanitize or restrict file extensions to expected deployment package types (`.zip`, `.war`, `.jar`).

```typescript
const resolvedPath = path.resolve(packagePath);
const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
if (!resolvedPath.startsWith(path.resolve(workspace))) {
  throw new Error('deployment-package-path must be within the workspace directory');
}
```

---

### H2: `exclude-patterns` Glob Injection

**File:** `src/deploymentpackage.ts:42-47`, `src/deploymentpackage.ts:64`

**Description:** The `exclude-patterns` input is split by comma and passed directly to `archiver.glob()` as ignore patterns without any sanitization:

```typescript
const excludePatterns = excludePatternsInput
  .split(',')
  .map(p => p.trim())
  .filter(p => p.length > 0);
// ...
archive.glob('**/*', { ignore: excludePatterns, dot: true });
```

While the `archiver` library's glob implementation uses `micromatch` or `minimatch` internally, crafted patterns could potentially cause:
1. **ReDoS (Regular Expression Denial of Service):** Extremely complex glob patterns could cause catastrophic backtracking.
2. **Unintended file inclusion:** Patterns like `!**/*.env` (negation) could be misinterpreted, causing sensitive files to be included in the deployment package.

Additionally, there is **no default exclusion** of sensitive files. Without explicit `exclude-patterns`, the action will package **everything** in the workspace (with `dot: true`), which could include `.env` files, `.git/` directories, private keys, credential files, and other secrets.

**Recommendation:**
- Add hardcoded default exclusions for sensitive patterns: `.env`, `.env.*`, `*.pem`, `*.key`, `.aws/`, `.git/`.
- Validate glob pattern length and complexity.
- Document the risk of including sensitive files clearly.

---

## Medium Severity

### M1: Unsafe Use of `any` Type Bypasses TypeScript Safety

**File:** `src/aws-operations.ts:461`, `src/aws-operations.ts:507`

**Description:** Both `updateEnvironment` and `createEnvironment` use `any` typed objects for AWS command parameters:

```typescript
const commandParams: any = {
  ApplicationName: applicationName,
  // ...
};
```

This disables TypeScript's type checking and could allow unexpected properties to be passed to AWS SDK commands. While this is more of a code quality issue, in security-critical infrastructure code, losing type safety increases the risk of subtle bugs that could lead to misconfigurations.

**Recommendation:** Use the proper AWS SDK types (`UpdateEnvironmentCommandInput`, `CreateEnvironmentCommandInput`) instead of `any`.

---

### M2: S3 Bucket Name Injection via `s3-bucket-name` Input

**File:** `src/aws-operations.ts:300`

**Description:** The `s3-bucket-name` input is used directly without validation:

```typescript
const bucket = customBucketName || `elasticbeanstalk-${region}-${accountId}`;
```

While the AWS SDK will reject truly malformed bucket names, there is no validation that the user-supplied bucket name follows S3 naming rules or belongs to the expected account. A misconfigured or malicious input could cause deployment packages to be uploaded to an attacker-controlled bucket.

The `verifyBucketOwnership` check (`src/aws-operations.ts:259-283`) helps mitigate this by verifying the bucket's ACL owner has write permissions and using `ExpectedBucketOwner`, but this only runs when `createBucketIfNotExists` is false. When bucket creation is enabled (the default), ownership is verified after creation, but a race condition could exist if the bucket name is predictable and an attacker pre-creates it.

**Recommendation:**
- Validate S3 bucket name format (3-63 chars, lowercase, no leading/trailing hyphens, etc.).
- Always verify `ExpectedBucketOwner` matches the caller's account ID on upload, not just on ACL check.
- Consider adding `ExpectedBucketOwner` to the `PutObjectCommand` as well.

---

### M3: JSON Parsing Without Schema Validation for `option-settings`

**File:** `src/validations.ts:125-135`, `src/aws-operations.ts:30`, `src/aws-operations.ts:450`

**Description:** The `option-settings` input is parsed with `JSON.parse()` and only checked for being an array. There is no schema validation of individual array elements. Malformed entries (missing `Namespace`, `OptionName`, or `Value` fields, or containing extra unexpected properties) are passed directly to the AWS SDK.

The `parseJsonInput` helper (`src/validations.ts:247-253`) also returns `any`, propagating untyped data:

```typescript
export function parseJsonInput(jsonString: string, inputName: string) {
  try {
    return JSON.parse(jsonString);
  } catch (error) {
    throw new Error(`Invalid JSON in ${inputName} input: ...`);
  }
}
```

While the AWS SDK will reject truly invalid structures, overly permissive parsing could lead to unexpected option settings being applied to Elastic Beanstalk environments.

**Recommendation:**
- Define a TypeScript interface for option settings entries.
- Validate each entry in the array has required fields (`Namespace`, `OptionName`, `Value`) and they are all strings.
- Add a return type to `parseJsonInput`.

---

### M4: Error Messages May Leak Sensitive Information

**File:** `src/main.ts:198`, `src/aws-operations.ts:132-134`, `src/aws-operations.ts:212`

**Description:** Error messages throughout the codebase include raw error objects, which could contain sensitive information from AWS API responses (e.g., account IDs, ARNs, internal AWS error details):

```typescript
// main.ts:198
core.error(`❌ Deployment failed after ${totalTime}s: ${(error as Error).message}`);

// aws-operations.ts:132-134
const errorMessage = `${operationName} failed after ${maxRetries} attempts: ${lastError?.message}`;
core.error(errorMessage);

// aws-operations.ts:212
throw new Error(`Failed to get S3 location for application version ${versionLabel}: ${error}`);
```

In GitHub Actions, these error messages appear in workflow logs that may be visible to all repository collaborators.

**Recommendation:**
- Sanitize error messages before logging to remove potential sensitive data.
- Use `core.debug()` for detailed error information and `core.error()` for user-friendly messages.
- Avoid string-interpolating raw error objects (line 212 uses `${error}` which calls `.toString()` on the full error).

---

## Low Severity

### L1: Missing `permissions` Block in Example Workflows

**File:** `examples/nodejs.yml`, `examples/docker.yml`, `examples/corretto.yml`

**Description:** Three of the five example workflows do not specify a `permissions` block. While `examples/python.yml` and `examples/go.yml` correctly scope permissions with `id-token: write` and `contents: read`, the other three use static credentials and rely on the default `GITHUB_TOKEN` permissions.

Following the principle of least privilege, all workflow examples should explicitly declare the minimum permissions they need, even if they only use `contents: read`.

**Recommendation:** Add explicit `permissions` blocks to all example workflows.

---

### L2: Static AWS Credentials Used in Examples

**File:** `examples/nodejs.yml:27-28`, `examples/docker.yml:27-28`, `examples/corretto.yml:40-41`

**Description:** Three example workflows demonstrate authentication using long-lived static credentials (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`):

```yaml
aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

While these are stored as secrets (not plaintext), static credentials are an inferior security practice compared to OIDC-based `role-to-assume` authentication, which the Python and Go examples correctly demonstrate. Static keys can be exfiltrated, have no automatic rotation, and provide persistent access.

**Recommendation:**
- Update all example workflows to use OIDC authentication (`role-to-assume`) as the primary pattern.
- If static credentials must be shown, add a comment noting OIDC is preferred and link to AWS documentation.

---

### L3: `createS3Bucket` Catches All Errors Silently

**File:** `src/aws-operations.ts:361`

**Description:** The `createS3Bucket` function catches all errors from `HeadBucketCommand` and assumes the bucket doesn't exist:

```typescript
} catch (_error) {
  core.info('🪣 S3 bucket does not exist, Creating S3 bucket');
```

`HeadBucketCommand` can return errors other than "bucket not found" - for example, `403 Forbidden` if the bucket exists but is owned by a different account. By catching all errors and attempting to create the bucket, the action could:
1. Mask permission errors.
2. Attempt to create a bucket that already exists under another account (which will fail, but the error handling hides the root cause).

**Recommendation:**
- Check the error type/status code. Only treat `404` (NotFound) as "bucket doesn't exist."
- Re-throw `403` errors with a clear message about bucket ownership.

---

### L4: `.gitignore` Does Not Exclude Sensitive Files

**File:** `.gitignore`

**Description:** The `.gitignore` file only excludes `/node_modules`, `/coverage`, and `.DS_Store`. It does not exclude common sensitive files such as `.env`, `.env.local`, `*.pem`, `*.key`, `.aws/credentials`, etc.

While this repository itself is a GitHub Action (not an application), contributors developing locally could accidentally commit sensitive files.

**Recommendation:** Add standard sensitive file patterns to `.gitignore`:
```
.env
.env.*
*.pem
*.key
.aws/
```

---

## Informational

### I1: No Dependency Pinning in GitHub Actions Workflows

**File:** `.github/workflows/check.yml:16`, `.github/workflows/package.yml:19`, `.github/workflows/release.yml:19-20`

**Description:** Third-party actions are referenced by major version tag (e.g., `actions/checkout@v4`, `actions/setup-node@v4`) rather than pinned to specific commit SHAs. While version tags are convenient, they can be force-updated by action maintainers, introducing a supply chain risk.

The `release.yml` uses `softprops/action-gh-release@v2` and `actions/attest-build-provenance@v2`, which are also not SHA-pinned.

**Recommendation:** Pin all third-party actions to their full commit SHAs:
```yaml
# Instead of:
uses: actions/checkout@v4
# Use:
uses: actions/checkout@<full-sha>
```

---

### I2: Deployment Package Created with `dot: true` Includes Hidden Files

**File:** `src/deploymentpackage.ts:64`

**Description:** The archive is created with `dot: true`:

```typescript
archive.glob('**/*', { ignore: excludePatterns, dot: true });
```

This includes all hidden/dotfiles in the deployment package (e.g., `.git/`, `.env`, `.npmrc`, `.ssh/`). While this is sometimes intentional (e.g., `.ebextensions/` is needed), it increases the risk of accidentally including sensitive configuration files in the deployed package.

**Recommendation:** Add default ignore patterns for known sensitive dotfiles/directories unless the user explicitly overrides them.

---

### I3: CNAMEPrefix Set to Environment Name Without Validation

**File:** `src/aws-operations.ts:511`

**Description:** When creating a new environment, the `CNAMEPrefix` is set directly from the user-provided `environmentName`:

```typescript
CNAMEPrefix: environmentName,
```

CNAME prefixes must be 4-63 characters, contain only letters/digits/hyphens, and not start/end with a hyphen. If the environment name doesn't meet these rules, the error will come from the AWS API rather than from input validation. This is a usability issue more than a security issue, but unclear error messages can lead to misconfiguration attempts.

**Recommendation:** Validate the environment name against CNAME prefix rules or allow `CNAMEPrefix` as a separate configurable input.

---

## Positive Security Practices

The codebase demonstrates several good security practices worth noting:

1. **S3 Bucket Ownership Verification** (`src/aws-operations.ts:259-283`): Uses `ExpectedBucketOwner` and ACL verification to confirm bucket ownership.
2. **Non-retryable Error Detection** (`src/aws-operations.ts:108-120`): Auth/permission errors fail fast instead of retrying, preventing credential-stuffing-like patterns.
3. **Deployment Package Size Limit** (`src/aws-operations.ts:309`): 500 MB hard limit prevents resource exhaustion.
4. **AWS Region Validation** (`src/validations.ts:39-43`): Strict regex validates region format.
5. **Numeric Input Bounds Checking** (`src/validations.ts:55-115`): All numeric inputs have min/max bounds.
6. **OIDC Authentication in Examples** (`examples/python.yml`, `examples/go.yml`): Best-practice authentication is demonstrated.
7. **Supply Chain Security in Releases** (`release.yml`): Artifact attestation and SHA256 checksums are generated.
8. **Streaming S3 Upload** (`src/aws-operations.ts:331`): Uses `createReadStream` instead of loading files into memory.
9. **IAM Role Validation for New Environments** (`src/aws-operations.ts:25-54`): Requires IAM settings when creating environments.
10. **Minimal Workflow Permissions** (`check.yml`): Uses `contents: read` only.

---

## Summary of Recommendations (Priority Order)

| Priority | Finding | Action |
|----------|---------|--------|
| 1 | H1: Path Traversal | Validate `deployment-package-path` is within `GITHUB_WORKSPACE` |
| 2 | H2: Glob Injection / Missing Default Exclusions | Add default exclusions for sensitive files, validate pattern complexity |
| 3 | M2: S3 Bucket Name Injection | Validate bucket name format, add `ExpectedBucketOwner` to `PutObjectCommand` |
| 4 | M3: Unvalidated JSON Schema | Add schema validation for `option-settings` entries |
| 5 | M1: `any` Type Usage | Replace with proper AWS SDK types |
| 6 | M4: Sensitive Info in Errors | Sanitize error messages in logs |
| 7 | L3: Silent Error Catching | Differentiate S3 error types in `createS3Bucket` |
| 8 | L1/L2: Example Improvements | Update examples with OIDC auth and explicit permissions |
| 9 | L4: `.gitignore` Gaps | Add sensitive file patterns |
| 10 | I1: Action Pinning | Pin third-party actions to commit SHAs |
