import { open, readdir, stat } from 'node:fs/promises'
import { basename, extname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const PE_MACHINE = {
  I386: 0x014c,
  AMD64: 0x8664,
  ARM64: 0xaa64
}

const MACHINE_NAME = {
  [PE_MACHINE.I386]: 'x86',
  [PE_MACHINE.AMD64]: 'x64',
  [PE_MACHINE.ARM64]: 'arm64'
}

async function readPeMachine(filePath) {
  const handle = await open(filePath, 'r')
  try {
    const mz = Buffer.alloc(2)
    if ((await handle.read(mz, 0, mz.length, 0)).bytesRead !== 2 || mz.toString('ascii') !== 'MZ') {
      throw new Error(`${filePath} is not a PE file (missing MZ header)`)
    }

    const peOffsetBuffer = Buffer.alloc(4)
    if ((await handle.read(peOffsetBuffer, 0, peOffsetBuffer.length, 0x3c)).bytesRead !== 4) {
      throw new Error(`${filePath} is not a valid PE file (truncated header)`)
    }
    const peOffset = peOffsetBuffer.readUInt32LE(0)

    const peHeader = Buffer.alloc(6)
    if ((await handle.read(peHeader, 0, peHeader.length, peOffset)).bytesRead !== 6) {
      throw new Error(`${filePath} is not a valid PE file (missing PE header)`)
    }
    if (peHeader.toString('ascii', 0, 4) !== 'PE\u0000\u0000') {
      throw new Error(`${filePath} is not a valid PE file (invalid PE signature)`)
    }

    return peHeader.readUInt16LE(4)
  } finally {
    await handle.close()
  }
}

async function collectWindowsBinaries(root, list = []) {
  const entries = await readdir(root, { withFileTypes: true })
  for (const entry of entries) {
    const filePath = join(root, entry.name)
    if (entry.isDirectory()) {
      await collectWindowsBinaries(filePath, list)
      continue
    }
    if (!entry.isFile()) continue
    const extension = extname(entry.name).toLowerCase()
    if (extension === '.exe' || extension === '.dll' || extension === '.node') {
      list.push(filePath)
    }
  }
  return list
}

async function findArm64Installer(releaseDir) {
  const entries = await readdir(releaseDir, { withFileTypes: true })
  const installers = entries
    .filter((entry) => entry.isFile() && /windows-arm64-setup\.exe$/i.test(entry.name))
    .map((entry) => join(releaseDir, entry.name))

  if (installers.length !== 1) {
    throw new Error(
      `Expected exactly one ARM64 installer matching *windows-arm64-setup.exe in ${releaseDir}, found ${installers.length}.`
    )
  }
  return installers[0]
}

export async function verifyWindowsArm64Artifacts(options = {}) {
  const releaseDir = resolve(options.releaseDir ?? 'dist')
  let unpackedDir = options.unpackedDir ? resolve(options.unpackedDir) : null
  if (!unpackedDir) {
    const candidates = [join(releaseDir, 'win-arm64-unpacked'), join(releaseDir, 'win-unpacked')]
    for (const cand of candidates) {
      const candidateStat = await stat(cand).catch(() => undefined)
      if (candidateStat?.isDirectory()) {
        unpackedDir = cand
        break
      }
    }
  }
  const installer = await findArm64Installer(releaseDir)

  const unpackedStat = unpackedDir ? await stat(unpackedDir).catch(() => undefined) : undefined
  if (!unpackedStat?.isDirectory()) {
    throw new Error(`Expected unpacked directory for ARM64 verification: ${unpackedDir ?? join(releaseDir, 'win-arm64-unpacked')}`)
  }

  const packagedNode = join(unpackedDir, 'resources', 'app', 'node_modules', 'node', 'bin', 'node.exe')
  const packagedNodeStat = await stat(packagedNode).catch(() => undefined)
  if (!packagedNodeStat?.isFile()) {
    throw new Error(
      `Packaged node.exe is missing at ${packagedNode}. Reinstall dependencies with lifecycle scripts and rebuild on a Windows ARM64 runner.`
    )
  }

  const binaries = await collectWindowsBinaries(unpackedDir)
  binaries.unshift(installer)

  const violations = []
  let nativeAddonCount = 0
  for (const file of binaries) {
    if (extname(file).toLowerCase() === '.node') nativeAddonCount += 1
    const machine = await readPeMachine(file)
    if (machine !== PE_MACHINE.ARM64) {
      const found = MACHINE_NAME[machine] ?? `0x${machine.toString(16)}`
      violations.push(`${relative(releaseDir, file)} => ${found}`)
    }
  }

  if (nativeAddonCount === 0) {
    throw new Error(
      `No native .node modules were found under ${unpackedDir}. The package is likely incomplete and cannot be trusted for ARM64 release.`
    )
  }

  if (violations.length > 0) {
    throw new Error(
      `Non-ARM64 binaries detected in Windows ARM64 package:\n${violations.join('\n')}\nRebuild on a Windows ARM64 machine and verify native dependencies (node, koffi, node-pty, harness runtime).`
    )
  }

  console.log(
    `Verified Windows ARM64 artifacts: installer ${basename(installer)}, ${binaries.length} PE files, ${nativeAddonCount} native addons.`
  )
}

async function main() {
  const [releaseDirArg, unpackedDirArg] = process.argv.slice(2)
  await verifyWindowsArm64Artifacts({
    releaseDir: releaseDirArg || 'dist',
    unpackedDir: unpackedDirArg
  })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main()
}
