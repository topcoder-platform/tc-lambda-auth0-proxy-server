const redis = require('redis'),
    _ = require('lodash'),
    request = require('request'),
    md5 = require('md5'),
    jwt = require('jsonwebtoken')

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

    if (!_.isEmpty(event['body'])) {
        auth0Payload = typeof event['body'] === 'string' ? JSON.parse(event['body']) : event['body']
        // cache key is combination of : clientid-md5(client_secret)
        cacheKey = auth0Payload.client_id || ''
        clientId = cacheKey
        cacheKey += `-${md5(auth0Payload.client_secret)}` || ' '
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

    if (!_.isEmpty(redisUrl)) {
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
                            errorResponse.body = error
                            callback(null, errorResponse)
                        }
                        if (body.access_token) {
                            let token = body.access_token
                            // Time to live in cache
                            let ttl = getTokenExipryTime(token)
                            redisClient.set(cacheKey, token, 'EX', ttl)
                            console.log("Fetched from Auth0 for cache key: ", cacheKey)
                            successResponse.body = JSON.stringify({
                                access_token: token.toString(),
                                expires_in: ttl
                            })
                            callback(null, successResponse)
                        }
                        else {
                            errorResponse.body = new Error('Unknown Error')
                            callback(null, errorResponse)
                        }
                        redisClient.quit()
                    })
                }
            })
        })
    } else {
        errorResponse.body = "Empty redis url."
        callback(null, errorResponse)
    }
};
