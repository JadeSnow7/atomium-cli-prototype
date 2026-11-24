import { test } from 'node:test';
import assert from 'node:assert/strict';
import Module, { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = dirname(fileURLToPath(import.meta.url));
const appRoot = resolve(testDir, '..');
const clientEntry = resolve(appRoot, '.test-dist/packages/atomium-client/src/index.js');
const appEntry = resolve(appRoot, '.test-dist/apps/mobile/src/App.js');

const require = createRequire(import.meta.url);

function loadMobileApp() {
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

test('MobileApprovalApp renders heading, initial closed status, pending approvals counter, and connect button', () => {
  const React = require('react');
  const { renderToStaticMarkup } = require('react-dom/server');
  const { MobileApprovalApp } = loadMobileApp();

  const html = renderToStaticMarkup(React.createElement(MobileApprovalApp));
  assert.match(html, /<h1>Atomium Mobile \(Expo Skeleton\)<\/h1>/);
  assert.match(html, /<p>Remote link: closed<\/p>/);
  assert.match(html, /<p>Pending approvals: 0<\/p>/);
  assert.match(html, /<button[^>]*>Connect<\/button>/);
});
