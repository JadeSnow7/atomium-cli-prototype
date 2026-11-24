import { test } from 'node:test';
import assert from 'node:assert/strict';
import Module, { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = dirname(fileURLToPath(import.meta.url));
const appRoot = resolve(testDir, '..');
const clientEntry = resolve(appRoot, '.test-dist/packages/atomium-client/src/index.js');
const appEntry = resolve(appRoot, '.test-dist/apps/desktop/src/App.js');

const require = createRequire(import.meta.url);

function loadDesktopApp() {
  const originalResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, parent, isMain, options) {
    if (request === '@atomium/client') {
      return clientEntry;
    }
    return originalResolve.call(this, request, parent, isMain, options);
  };
  try {
    return require(appEntry);
  } finally {
    Module._resolveFilename = originalResolve;
  }
}

test('Desktop App renders heading, initial closed status, socket input, connect button, and event counter', () => {
  const React = require('react');
  const { renderToStaticMarkup } = require('react-dom/server');
  const { App } = loadDesktopApp();

  const html = renderToStaticMarkup(React.createElement(App));
  assert.match(html, /<h1>Atomium Desktop \(Thin Client\)<\/h1>/);
  assert.match(html, /<p>Daemon status: closed<\/p>/);
  assert.match(html, /<input[^>]*value="\/tmp\/atomiumd\.sock"/);
  assert.match(html, /<button[^>]*>Connect atomiumd<\/button>/);
  assert.match(html, /<p>Events received: 0<\/p>/);
});
