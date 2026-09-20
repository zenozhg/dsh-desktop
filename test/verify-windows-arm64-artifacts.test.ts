import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { verifyWindowsArm64Artifacts } from '../scripts/verify-windows-arm64-artifacts.mjs'

const roots: string[] = []

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('verify-windows-arm64-artifacts', () => {
  it('accepts ARM64 installer and unpacked binaries', async () => {
    const root = await fixture()
    await expect(verifyWindowsArm64Artifacts({ releaseDir: root })).resolves.toBeUndefined()
  })

  it('fails when any unpacked binary is not ARM64', async () => {
    const root = await fixture({ addonMachine: 0x8664 })
    await expect(verifyWindowsArm64Artifacts({ releaseDir: root })).rejects.toThrow(
      /Non-ARM64 binaries detected/
    )
  })
})

async function fixture(options?: { addonMachine?: number }): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'dsh-arm64-artifacts-'))
  roots.push(root)
  const releaseDir = root
  const unpackedDir = path.join(releaseDir, 'win-unpacked')
  const nodeBin = path.join(unpackedDir, 'resources', 'app', 'node_modules', 'node', 'bin')
  const nativeDir = path.join(unpackedDir, 'resources', 'app', 'node_modules', 'node-pty', 'build')

  await mkdir(nodeBin, { recursive: true })
  await mkdir(nativeDir, { recursive: true })
  await writeFile(
    path.join(releaseDir, 'dsh-desktop-windows-arm64-setup.exe'),
    createPe(0xaa64)
  )
  await writeFile(path.join(nodeBin, 'node.exe'), createPe(0xaa64))
  await writeFile(path.join(nativeDir, 'pty.node'), createPe(options?.addonMachine ?? 0xaa64))

  return releaseDir
}

function createPe(machine: number): Buffer {
  const buffer = Buffer.alloc(256)
  buffer.write('MZ', 0, 'ascii')
  buffer.writeUInt32LE(0x80, 0x3c)
  buffer.write('PE\u0000\u0000', 0x80, 'ascii')
  buffer.writeUInt16LE(machine, 0x84)
  return buffer
}
