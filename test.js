const lambda = require('./lambda')

// Authentication server setting 
let event = {
  body: {
    "grant_type": "client_credentials",
    "client_id": process.env.TEST_AUTH0_CLIENT_ID || '',
    "client_secret": process.env.TEST_AUTH0_CLIENT_SECRET || '',
    "audience": process.env.TEST_AUTH0_AUDIENCE || '',
    "auth0_url": process.env.TEST_AUTH0_URL || '',
    "fresh_token": process.env.TEST_FRESH_TOKEN || false
  }
}
lambda.handler(event, {}, function (callback, result) {
  console.log(result)
})
