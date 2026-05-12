#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const root = process.cwd()
const configs = process.argv.slice(2)
const configFiles = configs.length ? configs : ['src-tauri/tauri.conf.json']
const missing = []

function readJson(file) {
  const fullPath = path.resolve(root, file)
  return {
    dir: path.dirname(fullPath),
    fullPath,
    json: JSON.parse(fs.readFileSync(fullPath, 'utf8')),
  }
}

function checkPath(configPath, configDir, sourcePath, label) {
  const fullPath = path.resolve(configDir, sourcePath)
  if (!fs.existsSync(fullPath)) {
    missing.push(`${configPath}: ${label} -> ${sourcePath}`)
  }
}

function checkResourceMap(configPath, configDir, resources, label, options = {}) {
  if (!resources) return

  if (Array.isArray(resources)) {
    for (const sourcePath of resources) {
      checkPath(configPath, configDir, sourcePath, label)
    }
    return
  }

  const sourcePaths = options.valuesAreSources ? Object.values(resources) : Object.keys(resources)
  for (const sourcePath of sourcePaths) {
    checkPath(configPath, configDir, sourcePath, label)
  }
}

let effectiveBundleResources = null

for (const configFile of configFiles) {
  const { dir, json } = readJson(configFile)
  checkResourceMap(configFile, dir, json.bundle?.icon, 'bundle.icon')
  if (json.app?.trayIcon?.iconPath) {
    checkPath(configFile, dir, json.app.trayIcon.iconPath, 'app.trayIcon.iconPath')
  }

  // Tauri merges config files in order, and a later `bundle.resources` object
  // overrides an earlier one for platform-specific builds. Validate only the
  // effective (last-defined) resources map to avoid false positives.
  if (json.bundle?.resources !== undefined) {
    effectiveBundleResources = {
      configFile,
      dir,
      resources: json.bundle.resources,
    }
  }

  for (const [platform, platformConfig] of Object.entries(json.bundle ?? {})) {
    if (!platformConfig || typeof platformConfig !== 'object') continue
    for (const [packageType, packageConfig] of Object.entries(platformConfig)) {
      if (!packageConfig || typeof packageConfig !== 'object') continue
      checkResourceMap(
        configFile,
        dir,
        packageConfig.files,
        `bundle.${platform}.${packageType}.files`,
        { valuesAreSources: true },
      )
    }
  }
}

if (effectiveBundleResources) {
  checkResourceMap(
    effectiveBundleResources.configFile,
    effectiveBundleResources.dir,
    effectiveBundleResources.resources,
    'bundle.resources',
  )
}

if (missing.length) {
  console.error('Missing Tauri packaging resources:')
  for (const entry of missing) {
    console.error(`  - ${entry}`)
  }
  process.exit(1)
}

console.log(`Verified Tauri resources for ${configFiles.join(', ')}`)
