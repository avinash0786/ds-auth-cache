'use strict';

// Builds the Redis connection for DNIO services from environment variables.
//
// Precedence:
//   1. CACHE_SENTINELS (or a redis+sentinel:// URL)  -> Sentinel (HA cache: 1 primary + replicas)
//   2. CACHE_CLUSTER                                 -> Redis Cluster (unchanged behaviour)
//   3. CACHE_HOST / CACHE_PORT                       -> standalone (same as before)
//   4. REDIS_URL / CACHE_URL                         -> standalone, from the URL (only when CACHE_HOST is not set)
//   5. nothing set                                   -> localhost:6379 (same as before)
//
// With none of the new variables set, the connection is the same as before this change,
// so one build works with both the single-pod cache and the Sentinel cache.

const Redis = require('ioredis');

function parseHostList(list, defaultPort) {
    return String(list).split(',').map(s => s.trim()).filter(Boolean).map(s => {
        const [host, port] = s.split(':');
        return { host, port: parseInt(port, 10) || defaultPort };
    });
}

// redis+sentinel://[:password@]host1:26379,host2:26379[/masterName]
function parseSentinelUrl(url) {
    let rest = url.slice('redis+sentinel://'.length);
    let password;
    const at = rest.lastIndexOf('@');
    if (at !== -1) {
        const auth = rest.slice(0, at);
        password = decodeURIComponent(auth.includes(':') ? auth.slice(auth.indexOf(':') + 1) : auth) || undefined;
        rest = rest.slice(at + 1);
    }
    const [hosts, name] = rest.split('/');
    return { sentinels: hosts, name: name || undefined, password };
}

function getCacheConfig(env = process.env) {
    const url = env.REDIS_URL || env.CACHE_URL;
    let password = env.REDIS_PASSWORD || env.CACHE_PASSWORD || undefined;
    let sentinels = env.CACHE_SENTINELS;
    let name = env.CACHE_SENTINEL_MASTER;

    if (!sentinels && url && url.startsWith('redis+sentinel://')) {
        const parsed = parseSentinelUrl(url);
        sentinels = parsed.sentinels;
        name = name || parsed.name;
        password = password || parsed.password;
    }

    if (sentinels) {
        return {
            mode: 'sentinel',
            options: {
                sentinels: parseHostList(sentinels, 26379),
                name: name || 'mymaster',
                password,
                sentinelPassword: env.CACHE_SENTINEL_PASSWORD || password,
                // ioredis >= 5.3: follow +switch-master as soon as Sentinel announces it.
                failoverDetector: true,
                // Fail fast on a dead node instead of hanging on its address.
                connectTimeout: parseInt(env.CACHE_CONNECT_TIMEOUT, 10) || 3000,
                sentinelCommandTimeout: 1000,
                // A primary demoted to replica answers READONLY: reconnect (asks Sentinel again) and resend.
                reconnectOnError: err => (String(err && err.message).startsWith('READONLY') ? 2 : false),
            },
        };
    }

    if (env.CACHE_CLUSTER) {
        return {
            mode: 'cluster',
            nodes: parseHostList(env.CACHE_CLUSTER, 6379),
            options: password ? { redisOptions: { password } } : {},
        };
    }

    // CACHE_HOST wins over REDIS_URL: DNIO pods get both (configmap + dnio-secrets),
    // and earlier versions of this library only used CACHE_HOST/CACHE_PORT.
    if (url && !env.CACHE_HOST) {
        // Credentials in the URL win over REDIS_PASSWORD.
        return { mode: 'standalone', url, options: password ? { password } : {} };
    }

    const options = {
        host: env.CACHE_HOST || 'localhost',
        port: parseInt(env.CACHE_PORT, 10) || 6379,
    };
    if (password) options.password = password;
    return { mode: 'standalone', options };
}

// Options for clients that build their own connection (BullMQ, @fastify/redis).
// Not valid for Redis Cluster.
function redisOptions(extra = {}, env = process.env) {
    const cfg = getCacheConfig(env);
    if (cfg.mode === 'cluster') throw new Error('redisOptions() does not support CACHE_CLUSTER; use createRedisClient()');
    // BullMQ ignores a `url` key, so turn the URL into plain ioredis options.
    if (cfg.url) return { ...urlToOptions(cfg.url), ...cfg.options, ...extra };
    return { ...cfg.options, ...extra };
}

function urlToOptions(url) {
    const u = new URL(url);
    const o = { host: u.hostname || 'localhost', port: parseInt(u.port, 10) || 6379 };
    if (u.username) o.username = decodeURIComponent(u.username);
    if (u.password) o.password = decodeURIComponent(u.password);
    const db = parseInt(u.pathname.slice(1), 10);
    if (!Number.isNaN(db)) o.db = db;
    if (u.protocol === 'rediss:') o.tls = {};
    return o;
}

function createRedisClient(extra = {}, env = process.env) {
    const cfg = getCacheConfig(env);
    if (cfg.mode === 'cluster') {
        return new Redis.Cluster(cfg.nodes, { ...cfg.options, ...extra });
    }
    if (cfg.url) return new Redis(cfg.url, { ...cfg.options, ...extra });
    return new Redis({ ...cfg.options, ...extra });
}

// Safe one-line description for logs (no password).
function describeCacheConfig(cfg = getCacheConfig()) {
    if (cfg.mode === 'sentinel') {
        return `sentinel master=${cfg.options.name} sentinels=${cfg.options.sentinels.map(s => `${s.host}:${s.port}`).join(',')}`;
    }
    if (cfg.mode === 'cluster') return `cluster nodes=${cfg.nodes.map(n => `${n.host}:${n.port}`).join(',')}`;
    if (cfg.url) return `standalone url=${cfg.url.replace(/\/\/[^@/]*@/, '//***@')}`;
    return `standalone ${cfg.options.host}:${cfg.options.port}`;
}

// After the first 'ready', ask the server what it is and log a clear error when the
// configuration does not match (for example CACHE_HOST pointing at a Sentinel port).
function warnOnModeMismatch(client, logger, cfg = getCacheConfig()) {
    client.once('ready', () => {
        Promise.resolve(client.info('server')).then(info => {
            const m = /redis_mode:(\w+)/.exec(String(info));
            const serverMode = m ? m[1] : 'unknown';
            if (serverMode === 'sentinel' && cfg.mode !== 'sentinel') {
                logger.error('Cache host is a Redis Sentinel. Set CACHE_SENTINELS=<host>:26379 instead of CACHE_HOST/CACHE_PORT.');
            } else if (serverMode === 'cluster' && cfg.mode !== 'cluster') {
                logger.error('Cache host is a Redis Cluster node. Set CACHE_CLUSTER instead.');
            }
        }).catch(() => { /* INFO not allowed: nothing to check */ });
    });
}

module.exports = {
    getCacheConfig,
    redisOptions,
    createRedisClient,
    describeCacheConfig,
    warnOnModeMismatch,
};
