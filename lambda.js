const redis = require('redis'),
    _ = require('lodash'),
    request = require('request'),
    md5 = require('md5'),
    jwt = require('jsonwebtoken'),
    joi = require('@hapi/joi')

const ignoredClients = ['zYw8u52siLqHu7PmHODYndeIpD4vGe1R']

function validatePayload(event) {
    if (_.isEmpty(event['body'])) {
        return { error: getErrorResponse({ body: "Empty body." }) }
    }
    const auth0Payload = typeof event['body'] === 'string' ? JSON.parse(event['body']) : event['body']
    const { value, error } = schema.validate(auth0Payload)
    if (error != null) {
        return { error: getErrorResponse({ statusCode: 400, body: "Payload validation error: " + JSON.stringify(error.details) }) }
    }
    return { auth0Payload }
}

const schema = joi.object().keys({
    client_id: joi.string().required(),
    grant_type: joi.string().required(),
    client_secret: joi.string().required(),
    audience: joi.string().required(),
    auth0_url: joi.string().required(),
    fresh_token: joi.boolean()
})

let redisClient = null

function acquireRedisClient() {
    if (redisClient == null) {
        console.log("Creating new redis client")
        redisClient = createRedisClient()
    } else {
        const pong = redisClient.ping()
        if (!pong) {
            console.log("Redis connection lost, creating new redis client")
            redisClient = createRedisClient()
        }
    }
}

function createRedisClient() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379'
    const con = redis.createClient(redisUrl)
    con.on("error", function (err) {
        console.log(err)
    })
    return con
}

function getCacheKey(auth0Payload) {
    const copyAuth0Payload = {
        "client_id": auth0Payload.client_id,
        "audience": auth0Payload.audience,
        "client_secret": auth0Payload.client_secret,
    }
    return `${auth0Payload.client_id}-${md5(JSON.stringify(copyAuth0Payload))}`
}

function callAuth0(auth0Payload, cacheKey, callback) {
    const options = {
        url: auth0Payload.auth0_url,
        headers: { 'content-type': 'application/json' },
        body: {
            grant_type: auth0Payload.grant_type,
            client_id: auth0Payload.client_id,
            client_secret: auth0Payload.client_secret,
            audience: auth0Payload.audience
        },
        json: true
    }
    request.post(options, function (error, response, body) {
        if (error) {
            const errorResponse = getErrorResponse({ statusCode: response.statusCode, body: error })
            console.log(errorResponse)
            callback(null, errorResponse)
        }
        if (body.access_token && response.statusCode === 200) {
            console.log(`Fetched from Auth0 for client-id: ${cacheKey}`)
            const token = body.access_token
            const ttl = saveToRedisCache(cacheKey, token)
            callback(null, getSuccessResponse({ body: JSON.stringify({ access_token: token, expires_in: ttl }) }))
        } else {
            const errorResponse = getErrorResponse({ statusCode: response.statusCode, body: JSON.stringify(body) })
            console.log(errorResponse)
            callback(null, errorResponse)
        }
    })
}

function getFromRedisCache(auth0Payload, cacheKey, callback) {
    redisClient.get(cacheKey, function (err, token) {
        if (err) {
            console.log(err)
            callAuth0(auth0Payload, cacheKey, callback)
        } else {
            const ttl = getTokenExpiryTime(token)
            if (ttl > 0) {
                console.log(`Fetched from Redis Cache for cache key:  ${cacheKey}`)
                callback(null, getSuccessResponse({ body: JSON.stringify({ access_token: token, expires_in: ttl }) }))
            } else {
                console.log("Token expired in cache")
                callAuth0(auth0Payload, cacheKey, callback)
            }
        }
    })
}

function saveToRedisCache(cacheKey, token) {
    const ttl = getTokenExpiryTime(token)
    redisClient.set(cacheKey, token, 'EX', ttl)
    return ttl
}

/**
 * 
 * @param String token
 * @returns expiryTime in seconds 
 */
function getTokenExpiryTime(token) {
    if (!token) {
        return 0
    } else {
        const decodedToken = jwt.decode(token)
        const expiryTimeInMilliSeconds = (decodedToken.exp - 60) * 1000 - (new Date().getTime())
        return Math.floor(expiryTimeInMilliSeconds / 1000)
    }
}

function getErrorResponse(error) {
    const errorResponse = {
        statusCode: 500,
        body: 'something went wrong.'
    }
    return _.assign(errorResponse, error)
}

function getSuccessResponse(response) {
    const successResponse = {
        statusCode: 200,
        body: "Bye!"
    }
    return _.assign(successResponse, response)
}

exports.handler = (event, context, callback) => {
    context.callbackWaitsForEmptyEventLoop = false
    const { error, auth0Payload } = validatePayload(event)
    if (error) {
        callback(null, error)
    } else {
        acquireRedisClient()
        const cacheKey = getCacheKey(auth0Payload)
        console.log(`Request for ${cacheKey}`)
        const freshToken = JSON.parse(auth0Payload.fresh_token ? auth0Payload.fresh_token : 0)
            && !_.includes(ignoredClients, auth0Payload.clientId)
        if (freshToken) {
            console.log("Requested fresh token")
            callAuth0(auth0Payload, cacheKey, callback)
        } else {
            getFromRedisCache(auth0Payload, cacheKey, callback)
        }
    }
}
