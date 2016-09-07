var request = require('request');
var authURL = '<your api url>';  // Change to your auth API url

// Constructor
function ExampleApiAuth() {}

// Static methods
ExampleApiAuth.authenticate = function(id, password, callback) {
  var options = {
    url: authURL,
    method: 'GET',  // Change to your request method here
    headers: {
      'id': id,
      'password': password
    }
  };
  // send authentication request
  request(options, function(err, res, body){
    if(err || res.statusCode != 200) {
      callback(new Error("Fail to authenticate, staus code:" + res.statusCode));
    } else {
      var json = JSON.parse(body);
      console.log(json);
      if(json.tenantId) {
        callback(null, json.tenantId);
      } else {
        callback(null, id);
      }
    }
  });
};
// Export the class
module.exports = ExampleApiAuth;
