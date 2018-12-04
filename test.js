const lambda = require('./lambda')

// Authentication server setting 
let event = {
  body: {
    "grant_type": "client_credentials",
    "client_id": process.env.AUTH0_CLIENT_ID || '',
    "client_secret": process.env.AUTH0_CLIENT_SECRET || '',
    "audience": process.env.AUTH0_AUDIENCE || '',
    "auth0_url": process.env.AUTH0_URL || '',
    "token_cache_time ": process.env.DEFAULT_TOKEN_CACHE_TIME || 864000 // 24Hrs
  }
}
lambda.handler(event, {}, function (callback, result) {
  console.log(result)
})
