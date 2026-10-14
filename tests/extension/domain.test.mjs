// Casamento de domínio da extensão (src/extension/maindug/lib/domain.js).
// Rodar: node --test tests/extension/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHost, hostOfUrl, matchesHost } from '../../src/extension/maindug/lib/domain.js';

test('normalizeHost aceita domínio, URL e variações', () => {
    assert.equal(normalizeHost('github.com'), 'github.com');
    assert.equal(normalizeHost('https://www.GitHub.com/login?next=/'), 'github.com');
    assert.equal(normalizeHost('www.github.com:443/path'), 'github.com');
    assert.equal(normalizeHost('  MyBank.com.br  '), 'mybank.com.br');
});

test('normalizeHost recusa nomes que não são domínio', () => {
    for (const value of ['GitHub', '', '   ', null, undefined, 42, 'a..b.com', '.github.com', 'github.com.', 'git hub.com']) {
        assert.equal(normalizeHost(value), null, String(value));
    }
});

test('hostOfUrl só considera http e https', () => {
    assert.equal(hostOfUrl('https://login.mybank.com/entrar'), 'login.mybank.com');
    assert.equal(hostOfUrl('http://mybank.test:8080/'), 'mybank.test');
    assert.equal(hostOfUrl('chrome-extension://abc/popup.html'), null);
    assert.equal(hostOfUrl('file:///etc/passwd'), null);
    assert.equal(hostOfUrl('não é url'), null);
});

test('matchesHost: mesmo host ou subdomínio com fronteira de ponto', () => {
    assert.ok(matchesHost('mybank.com', 'mybank.com'));
    assert.ok(matchesHost('login.mybank.com', 'mybank.com'));
    assert.ok(matchesHost('a.b.mybank.com', 'mybank.com'));
});

test('matchesHost: domínios parecidos não casam (bug original: substring)', () => {
    assert.ok(!matchesHost('bank.com', 'mybank.com'));
    assert.ok(!matchesHost('ank.com', 'mybank.com'));
    assert.ok(!matchesHost('mybank.com.evil.io', 'mybank.com'));
    assert.ok(!matchesHost('evilmybank.com', 'mybank.com'));
    assert.ok(!matchesHost('mybank.com', 'login.mybank.com'));
});

test('matchesHost: valores ausentes e IPs', () => {
    assert.ok(!matchesHost(null, 'mybank.com'));
    assert.ok(!matchesHost('mybank.com', null));
    assert.ok(matchesHost('127.0.0.1', '127.0.0.1'));
    assert.ok(!matchesHost('10.127.0.0.1', '127.0.0.1'));
});
