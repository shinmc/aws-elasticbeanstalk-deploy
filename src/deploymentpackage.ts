import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import archiver from 'archiver';

/**
 * Creates a deployment package for Elastic Beanstalk
 * @param packagePath - Path to existing package (optional)
 * @param versionLabel - Version label for the deployment
 * @param excludePatternsInput - Comma-separated patterns to exclude
 * @returns Object containing the path to the deployment package
 */
export async function createDeploymentPackage(
  packagePath: string | undefined,
  versionLabel: string,
  excludePatternsInput: string
): Promise<{ path: string }> {
  if (packagePath) {
    // Validate that the package path is within the workspace to prevent path traversal
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    const resolvedPackagePath = path.resolve(packagePath);
    const resolvedWorkspace = path.resolve(workspace);
    if (!resolvedPackagePath.startsWith(resolvedWorkspace + path.sep) && resolvedPackagePath !== resolvedWorkspace) {
      throw new Error(
        `deployment-package-path '${packagePath}' resolves outside the workspace directory. ` +
        'The path must point to a file within the GitHub Actions workspace.'
      );
    }

    if (!fs.existsSync(resolvedPackagePath)) {
      throw new Error(
        `deployment-package-path '${packagePath}' does not exist. ` +
        'Either provide a valid file path or omit deployment-package-path to have the action create a package automatically.'
      );
    }

    const stats = fs.statSync(resolvedPackagePath);
    if (!stats.isFile()) {
      throw new Error(
        `deployment-package-path '${packagePath}' is not a file. ` +
        'It must point to an existing deployment archive file (e.g., .zip, .war).'
      );
    }

    core.info(`📦 Using existing deployment package: ${resolvedPackagePath}`);
    return { path: resolvedPackagePath };
  }

  // No explicit package path provided – create a new deployment package from the workspace.
  const zipFileName = `deploy-${versionLabel}.zip`;
  core.info(`📦 Creating deployment package: ${zipFileName}`);

  const excludePatterns = excludePatternsInput
    .split(',')
    .map(p => p.trim())
    .filter(p => p.length > 0);

  await createZipFile(zipFileName, excludePatterns);

  return { path: zipFileName };
}

/**
 * Creates a zip file using archiver
 */
async function createZipFile(zipFileName: string, excludePatterns: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipFileName);
    const archive = archiver('zip');

    output.on('close', () => resolve());
    archive.on('error', reject);

    archive.pipe(output);
    archive.glob('**/*', { ignore: excludePatterns, dot: true });
    archive.finalize();
  });
}
