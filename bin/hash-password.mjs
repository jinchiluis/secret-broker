#!/usr/bin/env node
// Run this yourself, interactively: node bin/hash-password.mjs
// Prompts for the approver password with the terminal echo off, hashes it
// with scrypt, and prints only the hash. The plaintext password is never
// written anywhere and never leaves this terminal.
import { hashPassword } from '../src/auth.mjs';

function readHidden(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let input = '';
    const onData = (char) => {
      if (char === '\n' || char === '\r' || char === '') {
        stdin.setRawMode?.(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(input);
        return;
      }
      if (char === '') process.exit(130); // Ctrl-C
      if (char === '') {
        input = input.slice(0, -1);
        return;
      }
      input += char;
    };
    stdin.on('data', onData);
  });
}

const first = await readHidden('New approver password: ');
const second = await readHidden('Confirm: ');

if (first !== second) {
  console.error('Passwords did not match.');
  process.exit(1);
}
if (first.length < 12) {
  console.error('Use at least 12 characters.');
  process.exit(1);
}

console.log('\nAPPROVER_PASSWORD_HASH=' + hashPassword(first));
console.log('\nPaste that line into /etc/secret-broker/broker.env, then restart the broker.');
