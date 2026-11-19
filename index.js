const crypto = require('crypto');
const bluebird = require('bluebird');
const JWT = require('jsonwebtoken');
const log4js = require('log4js');
const version = require('./package.json').version;
const _ = require('lodash');
const redisOpts = require('./redis-options');

let logger = global.logger;

if (!logger) {
    logger = log4js.getLogger(`[ds-auth-cache] [${version}]`);
    logger.level = process.env.LOG_LEVEL || 'info';
}

function AuthCache() {
    const cfg = redisOpts.getCacheConfig();
    logger.info(`Connecting to cache :: ${redisOpts.describeCacheConfig(cfg)}`);
    this.client = redisOpts.createRedisClient();
    redisOpts.warnOnModeMismatch(this.client, logger, cfg);
    this.client = bluebird.promisifyAll(this.client);
    this.client.on('error', function (err) {
        logger.error(err.message);
    });
    this.client.on('connect', function () {
        logger.info('Cache client connected');
    });
}

AuthCache.prototype.isConnected = function () {
    logger.trace(`Cache connection status : ${this.client.status}, ${this.client.status == 'ready'}`)
    return this.client.status == 'ready';
}

AuthCache.prototype.isValidToken = async function (username, token) {
    let temp = await this.client.getAsync(`user:${username}`);
    if (!temp) {
        return false;
    }
    if (typeof temp == 'string') {
        temp = JSON.parse(temp);
    }
    if (Array.isArray(temp) && temp.indexOf(token) > -1) {
        return true;
    }
    return false;
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
    await this.client.del(`data:${username}`);
}

AuthCache.prototype.blacklistToken = async function (token) {
    const ttl = parseInt(process.env.RBAC_USER_TOKEN_DURATION || '600')
    await this.client.setAsync(`token:${token}`, 'BLACKLIST', 'EX', ttl);
}

AuthCache.prototype.isTokenBlacklisted = async function (token) {
    const data = await this.client.existsAsync(`token:${token}`);
    if (data) {
        return true;
    }
    return false;
}

AuthCache.prototype.getData = async function (username) {
    let data = await this.client.getAsync(`data:${username}`);
    if (data && typeof data === 'string') {
        try {
            data = JSON.parse(data);
        } catch (err) {
            logger.error('Data Parse Error');
        }
    }
    return data;
};

AuthCache.prototype.setData = async function (username, data) {
    let temp = await this.getData(username);
    if (temp) {
        data = _.merge(temp, data);
    }
    const ttl = parseInt(process.env.RBAC_USER_TOKEN_DURATION || '600')
    await this.client.setAsync(`data:${username}`, JSON.stringify(data), 'EX', ttl);
};

AuthCache.prototype.clearData = async function (username) {
    await this.client.del(`data:${username}`);
};

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
    await this.client.setAsync(`hb:${token}:${heartbeatId}`, 'WHITELIST', 'EX', ttl);
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
            if (options.permittedUrls.some(_url => compareURL(_url, req.path)) || req.path.indexOf('/internal/health') > -1 || req.path.indexOf('/utils/export') > -1) {
                return next();
            }
            logger.debug(`[${req.header('txnId')}] Validating token format`);
            let token = req.header('authorization');

            if (!token && req.cookies) {
                logger.debug(`[${req.header('txnId')}] No token found in 'authorization' header`);
                logger.debug(`[${req.header('txnId')}] Checking for 'authorization' token in cookie`);
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
                logger.error(`[${req.header('txnId')}] Invalid JWT format`);
                return res.status(401).json({ 'message': 'Unauthorized' });
            }

            if (typeof user === 'string') {
                user = JSON.parse(user)
            }

            const dataFromCache = await authCache.getData(user._id);
            if (dataFromCache && dataFromCache.userData) {
                user = Object.assign(user, dataFromCache.userData);
                if (!user.apps) {
                    user.apps = [];
                }
                if (user.accessControl && user.accessControl.apps) {
                    user.apps = user.accessControl.apps.map(e => e._id);
                }
            }

            let tokenHash = md5(token);
            logger.debug(`[${req.header('txnId')}] Token hash :: ${tokenHash}`);
            req.tokenHash = tokenHash;

            logger.trace(`[${req.header('txnId')}] Token Data : ${JSON.stringify(user)}`);

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
            logger.error(`[${req.header('txnId')}]`, err);
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
        logger.trace(`Compare URL :: ${tempUrl}, ${url} :: ${flag}`);
        return flag;
    }
    function md5(text) {
        return crypto.createHash('md5').update(text).digest('hex');
    }
}

module.exports = {
    AuthCache,
    AuthCacheMW,
    getCacheConfig: redisOpts.getCacheConfig,
    redisOptions: redisOpts.redisOptions,
    createRedisClient: redisOpts.createRedisClient,
    describeCacheConfig: redisOpts.describeCacheConfig,
};
