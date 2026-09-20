export interface VerifyWindowsArm64ArtifactsOptions {
  releaseDir?: string
  unpackedDir?: string
}

export function verifyWindowsArm64Artifacts(
  options?: VerifyWindowsArm64ArtifactsOptions
): Promise<void>
