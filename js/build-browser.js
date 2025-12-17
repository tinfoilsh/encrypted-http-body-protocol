#!/usr/bin/env node

/**
 * Build script to create a browser-compatible bundle
 */

const { build } = require('esbuild');
const { writeFileSync } = require('fs');
const { join } = require('path');

async function buildBrowser() {
  console.log('Building browser bundle...');

  try {
    // Build the main bundle
    await build({
      entryPoints: ['src/index.ts'],
      bundle: true,
      outfile: 'dist/browser.js',
      format: 'esm',
      target: 'es2020',
      platform: 'browser',
      external: [],
      sourcemap: true,
      minify: false,
      define: {
        'process.env.NODE_ENV': '"production"',
      },
    });

    // Create a simple wrapper that exports everything
    const wrapper = `
// Browser-compatible wrapper for EHBP client
export * from './browser.js';
`;

    writeFileSync(join(__dirname, 'dist', 'index.js'), wrapper);

    console.log('Browser bundle created successfully!');
    console.log('Files created:');
    console.log('  - dist/browser.js (main bundle)');
    console.log('  - dist/index.js (wrapper)');
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

buildBrowser();
