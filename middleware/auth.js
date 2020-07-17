// https://github.com/auth0/node-jsonwebtoken
// refresh token: https://github.com/jppellerin/node-jsonwebtoken/tree/refresh-token
// expiry: https://github.com/vercel/ms
const cs = require('../constants');
const HttpStatus = require('http-status-codes');

var jwt = require('jsonwebtoken');
const APIError = require('../error-handler/base-error');
const secret = 'secure@123';

const auth = {
    secure(payload) {
        return jwt.sign({ data: payload }, secret, { expiresIn: cs.TOKEN_EXPIRY });
    },

    verify(req, res, next) {
        const token = req.header('authorization');
        if (!token) throw new APIError(cs.NO_TOKEN, HttpStatus.UNAUTHORIZED);
        try {
            const decoded = jwt.verify(token, secret);
            req.user = decoded.user;
            next();
        } catch (err) {
            console.error(err);
            next(err);
        }
    },

    refresh(req, res) {
        var originalDecoded = jwt.decode(token, { complete: true });
        var refreshed = jwt.refresh(originalDecoded, 3600, secret);

        console.log(JSON.stringify(originalDecoded));
        // new 'exp' value is later in the future.
        console.log(JSON.stringify(jwt.decode(refreshed, { complete: true })));
    }
};

module.exports = auth;
