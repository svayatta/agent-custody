#!/usr/bin/env node

// Script to verify door Worker deployment after real credentials are provided
// Usage: node verify-deployment.mjs [worker-url] [log-url] [tenant-id]

import { spawn } from 'child_process';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';

const args = process.argv.slice(2);
const WORKER_URL = args[0] || process.env.WORKER_URL;
const LOG_URL = args[1] || process.env.LOG_URL;
const TENANT_ID = args[2] || process.env.TENANT_ID;

if (!WORKER_URL || !LOG_URL || !TENANT_ID) {
  console.error('Error: Missing required arguments or environment variables');
  console.error('Usage: node verify-deployment.mjs [worker-url] [log-url] [tenant-id]');
  console.error('Or set WORKER_URL, LOG_URL, TENANT_ID environment variables');
  process.exit(1);
}

const KEYS_DIR = './keys';
const DOOR_KEY_PATH = join(KEYS_DIR, 'door.key');
const DOOR_PUB_PATH = join(KEYS_DIR, 'door.pub');

// Helper function to run commands
function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, { ...options, stdio: 'pipe' });
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Command failed: ${command} ${args.join(' ')}\n${stderr}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

// Helper function to run curl commands
async function curl(url, options = {}) {
  const args = ['-s', url];
  if (options.headers) {
    options.headers.forEach(header => args.push('-H', header));
  }
  if (options.method) {
    args.push('-X', options.method);
  }
  if (options.data) {
    args.push('-d', options.data);
  }
  
  try {
    return await runCommand('curl', args);
  } catch (error) {
    console.error(`CURL failed for ${url}:`, error.message);
    throw error;
  }
}

// Generate report
function generateReport(testResults) {
  const report = {
    timestamp: new Date().toISOString(),
    workerUrl: WORKER_URL,
    logUrl: LOG_URL,
    tenantId: TENANT_ID,
    tests: testResults,
    summary: {
      total: testResults.length,
      passed: testResults.filter(t => t.passed).length,
      failed: testResults.filter(t => !t.passed).length
    }
  };
  
  const reportPath = join(__dirname, 'deployment-report.json');
  writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\nReport saved to: ${reportPath}`);
  
  return report;
}

// Main verification function
async function verifyDeployment() {
  console.log('Starting door Worker deployment verification...');
  
  // Check if keys exist
  if (!existsSync(DOOR_PUB_PATH)) {
    console.error('Door public key not found. Run agent-custody keygen first.');
    process.exit(1);
  }
  
  const doorPubKey = readFileSync(DOOR_PUB_PATH, 'utf8');
  console.log('Using door public key from:', DOOR_PUB_PATH);
  
  const testResults = [];
  
  try {
    // Test 1: Check if worker is accessible
    console.log('\n1. Testing worker accessibility...');
    const response = await curl(`${WORKER_URL}/.well-known/agent-custody-door`);
    if (response) {
      testResults.push({
        name: 'Worker Accessibility',
        passed: true,
        details: 'Worker is accessible'
      });
      console.log('✓ Worker is accessible');
    } else {
      throw new Error('Worker not accessible');
    }
    
    // Test 2: Allowed request (GET /products/1)
    console.log('\n2. Testing allowed request...');
    const allowedResponse = await curl(`${WORKER_URL}/products/1`);
    const allowedHeaders = allowedResponse.split('\n').find(h => h.toLowerCase().startsWith('x-agent-custody'));
    
    if (allowedHeaders && allowedResponse.includes('200')) {
      const receiptId = allowedHeaders.match(/x-agent-custody-receipt:\s*(\S+)/)?.[1];
      testResults.push({
        name: 'Allowed Request',
        passed: true,
        details: 'Request allowed with receipt',
        receiptId
      });
      console.log('✓ Allowed request successful with receipt:', receiptId);
      
      // Fetch and verify allowed receipt
      if (receiptId) {
        console.log('\n2a. Fetching and verifying allowed receipt...');
        try {
          await runCommand('npx', ['wrangler@4', 'r2', 'object', 'get', 'agent-custody-door-receipts', `${receiptId}.json`, '--file', 'allowed-receipt.json', '--remote']);
          await runCommand('npx', ['-y', '-p', '@agent-custody/receipts', 'agent-custody', 'verify', 'allowed-receipt.json', '--issuer-key', DOOR_PUB_PATH, '--log-url', LOG_URL]);
          testResults.push({
            name: 'Allowed Receipt Verification',
            passed: true,
            details: 'Receipt verified successfully'
          });
          console.log('✓ Allowed receipt verified');
        } catch (error) {
          testResults.push({
            name: 'Allowed Receipt Verification',
            passed: false,
            details: error.message
          });
          console.error('✗ Allowed verification failed:', error.message);
        }
      }
    } else {
      throw new Error('Allowed request failed');
    }
    
    // Test 3: Refused request (POST /orders)
    console.log('\n3. Testing refused request...');
    const refusedResponse = await curl(`${WORKER_URL}/orders`, {
      method: 'POST',
      headers: ['content-type: application/json'],
      data: JSON.stringify({ sku: 'tea', qty: 1 })
    });
    
    if (refusedResponse.includes('403')) {
      const refusedHeaders = refusedResponse.split('\n').find(h => h.toLowerCase().startsWith('x-agent-custody'));
      const receiptId = refusedHeaders?.match(/x-agent-custody-receipt:\s*(\S+)/)?.[1];
      testResults.push({
        name: 'Refused Request',
        passed: true,
        details: 'Request refused with receipt',
        receiptId
      });
      console.log('✓ Refused request successful with receipt:', receiptId);
      
      // Fetch and verify refused receipt
      if (receiptId) {
        console.log('\n3a. Fetching and verifying refused receipt...');
        try {
          await runCommand('npx', ['wrangler@4', 'r2', 'object', 'get', 'agent-custody-door-receipts', `${receiptId}.json`, '--file', 'refused-receipt.json', '--remote']);
          await runCommand('npx', ['-y', '-p', '@agent-custody/receipts', 'agent-custody', 'verify', 'refused-receipt.json', '--issuer-key', DOOR_PUB_PATH, '--log-url', LOG_URL]);
          testResults.push({
            name: 'Refused Receipt Verification',
            passed: true,
            details: 'Receipt verified successfully'
          });
          console.log('✓ Refused receipt verified');
        } catch (error) {
          testResults.push({
            name: 'Refused Receipt Verification',
            passed: false,
            details: error.message
          });
          console.error('✗ Refused verification failed:', error.message);
        }
      }
    } else {
      throw new Error('Refused request failed');
    }
    
    // Generate final report
    const report = generateReport(testResults);
    
    console.log('\n=== VERIFICATION SUMMARY ===');
    console.log(`Total tests: ${report.summary.total}`);
    console.log(`Passed: ${report.summary.passed}`);
    console.log(`Failed: ${report.summary.failed}`);
    
    if (report.summary.failed === 0) {
      console.log('\n🎉 All tests passed! Deployment verification successful.');
      process.exit(0);
    } else {
      console.log('\n❌ Some tests failed. Check the report for details.');
      process.exit(1);
    }
    
  } catch (error) {
    console.error('Verification failed:', error.message);
    process.exit(1);
  }
}

// Run verification
verifyDeployment();