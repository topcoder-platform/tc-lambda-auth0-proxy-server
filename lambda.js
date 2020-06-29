const redis = require('redis'),
    _ = require('lodash'),
    request = require('request'),
    md5 = require('md5'),
    jwt = require('jsonwebtoken'),
    joi = require('@hapi/joi')

const schema = joi.object().keys({
    client_id: joi.string().required(),
    grant_type: joi.string().required(),
    client_secret: joi.string().required(),
    audience: joi.string().required(),
    auth0_url: joi.string().required(),
    fresh_token: joi.boolean()
})

/**
 * 
 * @param String token
 * @returns expiryTime in seconds 
 */
function getTokenExipryTime(token) {
    let expiryTime = 0
    if (token) {
        let decodedToken = jwt.decode(token)
        let expiryTimeInMilliSeconds = (decodedToken.exp - 60) * 1000 - (new Date().getTime())
        expiryTime = Math.floor(expiryTimeInMilliSeconds / 1000)
    }
    return expiryTime
}

exports.handler = (event, context, callback) => {
    let redisUrl = process.env.REDIS_URL || 'redis://localhost:6379'
    let auth0Payload = {}
    let cacheKey = ''
    let clientId = ''
    let options = {}
    let redisClient = null
    let errorResponse = {
        statusCode: 500,
        body: 'something went wrong.'
    }
    let successResponse = {
        statusCode: 200,
        body: "Bye!"
    }
    let freshToken = false
    let payloadValidationError = false

    if (!_.isEmpty(event['body'])) {
        auth0Payload = typeof event['body'] === 'string' ? JSON.parse(event['body']) : event['body']
        // cache key is combination of : clientid
        const { value, error } = schema.validate(auth0Payload)
        if (error != null) {
            payloadValidationError = true
            errorResponse.statusCode = 400
            errorResponse.body = "Payload validation error: " + JSON.stringify(error.details)
        }
        clientId = auth0Payload.client_id || ''
        secret = _.get(auth0Payload, 'client_secret', '')
        cacheKey = `${clientId}-${md5(secret)}` || ' '
        options = {
            url: auth0Payload.auth0_url,
            headers: { 'content-type': 'application/json' },
            body: auth0Payload,
            json: true
        }
        freshToken = JSON.parse(auth0Payload.fresh_token ? auth0Payload.fresh_token : 0)

    } else {
        errorResponse.body = "Empty body."
        callback(null, errorResponse)
    }

    if (!_.isEmpty(redisUrl) && !payloadValidationError) {
        redisClient = redis.createClient(redisUrl)
        redisClient.on("error", function (err) {
            errorResponse.body = "redis client connecting error: " + err
            callback(null, errorResponse)
            redisClient.quit()
        })
        redisClient.on("ready", () => {
            // try to get token from cache first 
            redisClient.get(cacheKey, function (err, token) {
                // todo err implementation
                if (token != null && !freshToken && getTokenExipryTime(token.toString()) > 0) {
                    console.log("Fetched from Redis Cache for cache key: ", clientId)
                    successResponse.body = JSON.stringify({
                        access_token: token.toString(),
                        expires_in: getTokenExipryTime(token.toString())
                    })
                    callback(null, successResponse)
                    redisClient.quit()
                }
                else {
                    request.post(options, function (error, response, body) {
                        if (error) {
                            errorResponse.statusCode = response.statusCode
                            errorResponse.body = error
                            callback(null, errorResponse)
                        }
                        if (body.access_token && response.statusCode === 200) {
                            let token = body.access_token
                            // Time to live in cache
                            let ttl = getTokenExipryTime(token)
                            redisClient.set(cacheKey, token, 'EX', ttl)
                            console.log("Fetched from Auth0 for client-id: ", clientId)
                            successResponse.body = JSON.stringify({
                                access_token: token.toString(),
                                expires_in: ttl
                            })
                            callback(null, successResponse)
                        } else {
                            errorResponse.statusCode = response.statusCode
                            errorResponse.body = JSON.stringify(body)
                            callback(null, errorResponse)
                        }
                        redisClient.quit()
                    })
                }
            })
        })
    } else if (payloadValidationError) {
        callback(null, errorResponse)
    } else {
        errorResponse.body = "Empty redis url or payload validation error."
        callback(null, errorResponse)
    }
};
