const redis = require('redis'),
    _ = require('lodash'),
    request = require('request'),
    md5 = require('md5')

exports.handler = (event, context, callback) => {
    let redisUrl = process.env.REDIS_URL
    let auth0Payload = {}
    let cacheKey = ''
    let tokenCacheTime = process.env.DEFAULT_TOKEN_CACHE_TIME || 86400
    let options = {}
    if (!_.isEmpty(event['body'])) {
        auth0Payload = typeof event['body'] === 'string' ? JSON.parse(event['body']) : event['body']
        // cache key is combination of : clientid-md5(client_secret)
        cacheKey = auth0Payload.client_id || ''
        cacheKey += `-${md5(auth0Payload.client_secret)}` || ' '
        tokenCacheTime = auth0Payload.token_cache_time || tokenCacheTime
        options = {
            url: auth0Payload.auth0_url,
            headers: { 'content-type': 'application/json' },
            body: auth0Payload,
            json: true
        }
    }

    let redisClient = null
    let errorResponse = {
        statusCode: 500,
        body: 'something went wrong.'
    }
    let successResponse = {
        statusCode: 200,
        body: "Bye!"
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
                if (token != null) {
                    console.log("Fetched from Redis Cache for cache key: ", cacheKey)
                    //successResponse.body = JSON.stringify({ access_token: token.toString() })
                    redisClient.ttl(cacheKey, function (err, ttl) {
                        if (ttl != null) {
                            successResponse.body = JSON.stringify({ access_token: token.toString(), expires_in: ttl })
                            callback(null, successResponse)
                        }
                        else if (err) {
                            errorResponse.body = err
                            callback(null, errorResponse)
                        }
                        redisClient.quit()
                    })
                }
                else {
                    request.post(options, function (error, response, body) {
                        if (error) {
                            errorResponse.body = error
                            callback(null, errorResponse)
                        }
                        if (body.access_token) {
                            let token = body.access_token
                            let ttl = tokenCacheTime
                            if (body.expires_in) {
                                ttl = body.expires_in - 1 // less 1 sec for safer side
                            }
                            redisClient.set(cacheKey, token, 'EX', ttl)
                            console.log("Fetched from Auth0 for cache key: ", cacheKey)
                            successResponse.body = JSON.stringify({ access_token: token.toString(), expires_in: ttl - 1 }) // less 1 sec for safer side  
                            //close redis connection                           
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

    }
};