'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { getCacheConfig, redisOptions, describeCacheConfig } = require('../redis-options');

test('no env: standalone localhost:6379, as before', () => {
    const cfg = getCacheConfig({});
    assert.deepStrictEqual(cfg, { mode: 'standalone', options: { host: 'localhost', port: 6379 } });
});

test('CACHE_HOST/CACHE_PORT: standalone, no password unless set', () => {
    const cfg = getCacheConfig({ CACHE_HOST: 'cache', CACHE_PORT: '6380' });
    assert.deepStrictEqual(cfg.options, { host: 'cache', port: 6380 });
    const withPw = getCacheConfig({ CACHE_HOST: 'cache', REDIS_PASSWORD: 'p' });
    assert.strictEqual(withPw.options.password, 'p');
});

test('CACHE_PASSWORD is used when REDIS_PASSWORD is not set', () => {
    assert.strictEqual(getCacheConfig({ CACHE_PASSWORD: 'c' }).options.password, 'c');
});

test('CACHE_SENTINELS: sentinel mode with defaults', () => {
    const cfg = getCacheConfig({ CACHE_SENTINELS: 'cache-sentinel.dnio:26379', CACHE_HOST: 'cache', REDIS_PASSWORD: 'p' });
    assert.strictEqual(cfg.mode, 'sentinel');
    assert.deepStrictEqual(cfg.options.sentinels, [{ host: 'cache-sentinel.dnio', port: 26379 }]);
    assert.strictEqual(cfg.options.name, 'mymaster');
    assert.strictEqual(cfg.options.password, 'p');
    assert.strictEqual(cfg.options.sentinelPassword, 'p');
    assert.strictEqual(cfg.options.failoverDetector, true);
    assert.strictEqual(cfg.options.connectTimeout, 3000);
    assert.strictEqual(cfg.options.reconnectOnError(new Error('READONLY You can\'t write against a read only replica.')), 2);
    assert.strictEqual(cfg.options.reconnectOnError(new Error('ERR other')), false);
});

test('CACHE_SENTINELS: several hosts, default port, master name', () => {
    const cfg = getCacheConfig({ CACHE_SENTINELS: 's1, s2:26380', CACHE_SENTINEL_MASTER: 'dnio' });
    assert.deepStrictEqual(cfg.options.sentinels, [{ host: 's1', port: 26379 }, { host: 's2', port: 26380 }]);
    assert.strictEqual(cfg.options.name, 'dnio');
});

test('CACHE_SENTINELS wins over CACHE_CLUSTER', () => {
    assert.strictEqual(getCacheConfig({ CACHE_SENTINELS: 's1', CACHE_CLUSTER: 'n1' }).mode, 'sentinel');
});

test('redis+sentinel:// URL', () => {
    const cfg = getCacheConfig({ REDIS_URL: 'redis+sentinel://:s%40cret@s1:26379,s2/dnio' });
    assert.strictEqual(cfg.mode, 'sentinel');
    assert.deepStrictEqual(cfg.options.sentinels, [{ host: 's1', port: 26379 }, { host: 's2', port: 26379 }]);
    assert.strictEqual(cfg.options.name, 'dnio');
    assert.strictEqual(cfg.options.password, 's@cret');
});

test('CACHE_CLUSTER: unchanged cluster mode', () => {
    const cfg = getCacheConfig({ CACHE_CLUSTER: '10.0.0.1,10.0.0.2:7000' });
    assert.strictEqual(cfg.mode, 'cluster');
    assert.deepStrictEqual(cfg.nodes, [{ host: '10.0.0.1', port: 6379 }, { host: '10.0.0.2', port: 7000 }]);
    assert.deepStrictEqual(cfg.options, {});
    assert.throws(() => redisOptions({}, { CACHE_CLUSTER: 'n1' }));
});

test('REDIS_URL: standalone from URL', () => {
    const cfg = getCacheConfig({ REDIS_URL: 'redis://cache.dnio:6379' });
    assert.strictEqual(cfg.mode, 'standalone');
    assert.strictEqual(cfg.url, 'redis://cache.dnio:6379');
    assert.deepStrictEqual(redisOptions({ maxRetriesPerRequest: null }, { REDIS_URL: 'redis://cache.dnio:6379' }),
        { maxRetriesPerRequest: null, url: 'redis://cache.dnio:6379' });
});

test('describeCacheConfig never prints the password', () => {
    const d1 = describeCacheConfig(getCacheConfig({ REDIS_URL: 'redis://:secret@cache:6379' }));
    const d2 = describeCacheConfig(getCacheConfig({ CACHE_SENTINELS: 's1', REDIS_PASSWORD: 'secret' }));
    assert.ok(!d1.includes('secret') && !d2.includes('secret'), `${d1} | ${d2}`);
});
