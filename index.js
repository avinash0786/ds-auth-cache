const crypto = require('crypto');
const bluebird = require('bluebird');
const Redis = require('ioredis');
const JWT = require('jsonwebtoken');

const host = process.env.CACHE_HOST || 'localhost';
const port = process.env.CACHE_PORT ? parseInt(process.env.CACHE_PORT) : 6379;

let logger = global.logger;

if (!logger) {
    logger = {
        debug: console.log,
        trace: console.log,
        info: console.log,
        error: console.error,
    };
}

function getClusterNodes() {
    let nodes = [];
    //format: 127.0.0.1,127.0.0.2:8990 results in 127.0.0.1:6379 and 127.0.0.2:8990 respectively
    let clusterNodes = process.env.CACHE_CLUSTER.split(',');
    clusterNodes.map(node => {
        nodes.push({
            host: node.split(':')[0],
            port: node.split(':')[1] || '6379',
        });
    });
    return nodes;
}

function AuthCache() {
    this.client = null;
    if (process.env.CACHE_CLUSTER) {
        logger.info('[ds-auth-cache] Connecting to cache cluster');
        logger.info('[ds-auth-cache] Cache cluster nodes :: ', JSON.stringify(getClusterNodes()));
        this.client = new Redis.Cluster(getClusterNodes());
    } else {
        logger.info('[ds-auth-cache] Connecting to standalone cache');
        this.client = new Redis(port, host);
    }
    this.client = bluebird.promisifyAll(this.client);
    this.client.on('error', function (err) {
        logger.error('[ds-auth-cache]', err.message);
    });
    this.client.on('connect', function () {
        logger.info('[ds-auth-cache] Cache client connected');
    });
}

AuthCache.prototype.whitelistToken = async function (username, token) {
    let temp = await this.client.getAsync(`user:${username}`);
    if (!temp) {
        temp = [];
    }
    if (typeof temp == 'string') {
        temp = JSON.parse(temp);
    }
    temp.push(token);
    await this.client.setAsync(`user:${username}`, JSON.stringify(temp));
}

AuthCache.prototype.isSessionActive = async function (username) {
    let temp = await this.client.getAsync(`user:${username}`);
    if (!temp) {
        return false;
    }
    if (typeof temp == 'string') {
        temp = JSON.parse(temp);
    }
    if (Array.isArray(temp) && temp.length > 0) {
        return true;
    }
    return false;
}

AuthCache.prototype.endSession = async function (username) {
    let temp = await this.client.getAsync(`user:${username}`);
    if (!temp) {
        temp = [];
    }
    if (typeof temp == 'string') {
        temp = JSON.parse(temp);
    }
    temp.forEach(token => {
        this.blacklistToken(token);
    });
    await this.client.setAsync(`user:${username}`, JSON.stringify([]));
}

AuthCache.prototype.blacklistToken = async function (token) {
    const data = JWT.decode(token, { json: true });
    if (data && data.exp) {
        await this.client.setAsync(`token:${token}`, 'BLACKLIST', 'EXAT', data.exp);
    }
}

AuthCache.prototype.isTokenBlacklisted = async function (token) {
    const data = await this.client.existsAsync(`token:${token}`);
    if (data) {
        return true;
    }
    return false;
}

AuthCache.prototype.setUserPermissions = async function (username, permissions) {
    await this.client.setAsync(`perm:${username}`, JSON.stringify(permissions));
}

AuthCache.prototype.getUserPermissions = async function (username) {
    const temp = await this.client.getAsync(`perm:${username}`);
    return typeof temp === 'string' ? JSON.parse(temp) : [];
}

AuthCache.prototype.unsetUserPermissions = async function (username) {
    await this.client.del(`perm:${username}`);
}

AuthCache.prototype.setHeartbeatID = async function (token, heartbeatId, ttl) {
    await this.client.setAsync(`hb:${token}:${heartbeatId}`, 'WHITELIST', 'EXAT', ttl);
}

AuthCache.prototype.unsetHeartbeatID = async function (token, heartbeatId) {
    await this.client.del(`hb:${token}:${heartbeatId}`);
}

AuthCache.prototype.isHeartbeatValid = async function (token, heartbeatId) {
    const data = await this.client.existsAsync(`hb:${token}:${heartbeatId}`);
    if (data) {
        return true;
    }
    return false;
}


/**
 * @param {object} options
 * @param {string} options.secret The JWT token secret
 * @param {boolean} [options.decodeOnly] If true, it won't validate JWT Token
 * @param {string[]} [options.permittedUrls] List of URL that doesn't need JWT Token
 * @param {string} [options.app] App Can be provided for App specific services
 */
function AuthCacheMW(options) {
    const authCache = new AuthCache();
    if (!options) {
        throw new Error('Options is Required');
    }
    if (!options.secret) {
        throw new Error('Secret is Required');
    }
    if (!options.permittedUrls) {
        options.permittedUrls = [];
    }
    if (!options.decodeOnly) {
        options.decodeOnly = false;
    }
    return async function (req, res, next) {
        try {
            if (options.permittedUrls.some(_url => compareURL(_url, req.path)) || req.path.indexOf('/health') > -1 || req.path.indexOf('/export') > -1) {
                return next();
            }
            logger.debug(`[${req.header('txnId')}] [ds-auth-cache] Validating token format`);
            let token = req.header('authorization');

            if (!token && req.cookies) {
                logger.debug(`[${req.header('txnId')}] [ds-auth-cache] No token found in 'authorization' header`);
                logger.debug(`[${req.header('txnId')}] [ds-auth-cache] Checking for 'authorization' token in cookie`);
                token = req.cookies.Authorization;
            }

            if (!token) return res.status(401).json({ message: 'Unauthorized' });

            token = token.split('JWT ')[1];
            let user;
            if (options.decodeOnly) {
                user = JWT.decode(token, { json: true });
            } else {
                user = JWT.verify(token, options.secret, { ignoreExpiration: true });
            }
            if (!user) {
                logger.error(`[${req.header('txnId')}] [ds-auth-cache] Invalid JWT format`);
                return res.status(401).json({ 'message': 'Unauthorized' });
            }

            if (typeof user === 'string') {
                user = JSON.parse(user)
            }
            let tokenHash = md5(token);
            logger.debug(`[${req.header('txnId')}] [ds-auth-cache] Token hash :: ${tokenHash}`);
            req.tokenHash = tokenHash;

            logger.trace(`[${req.header('txnId')}] [ds-auth-cache] Token Data : ${JSON.stringify(user)}`);

            // Fetching from Redis Cache
            if (options.app) {
                user.appPermissions = (await authCache.getUserPermissions(user._id + '_' + options.app) || []);
            }
            const keys = (await authCache.client.keys(`perm:${user._id}*`) || []);
            const permissions = await Promise.all(keys.map(async (key) => {
                let perms = await authCache.client.get(key);
                const p = {};
                p.app = key.split('_').pop();
                p.permissions = typeof perms === 'string' ? JSON.parse(perms) : [];
                return p;
            }));
            user.allPermissions = permissions || [];
            Object.defineProperty(req, 'user', {
                configurable: true,
                enumerable: true,
                value: user
            });
            Object.defineProperty(req, 'authCache', {
                configurable: true,
                enumerable: true,
                value: authCache
            });
            next();
        } catch (err) {
            logger.error(`[${req.header('txnId')}] [ds-auth-cache]`, err);
            res.status(500).json({ message: err.message });
        }
    }

    function compareURL(tempUrl, url) {
        let tempUrlSegment = tempUrl.split("/").filter(_d => _d != "");
        let urlSegment = url.split("/").filter(_d => _d != "");
        if (tempUrlSegment.length != urlSegment.length) return false;

        tempUrlSegment.shift();
        urlSegment.shift();

        let flag = tempUrlSegment.every((_k, i) => {
            if (_k.startsWith("{") && _k.endsWith("}") && urlSegment[i] != "") return true;
            return _k === urlSegment[i];
        });
        logger.trace(`[ds-auth-cache] Compare URL :: ${tempUrl}, ${url} :: ${flag}`);
        return flag;
    }
    function md5(text) {
        return crypto.createHash('md5').update(text).digest('hex');
    }
}

module.exports = {
    AuthCache,
    AuthCacheMW
};