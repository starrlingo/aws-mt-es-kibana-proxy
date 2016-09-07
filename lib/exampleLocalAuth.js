var request   = require('request');

// Constructor
function ExampleLocalAuth() {
}

// Static methods
ExampleLocalAuth.authenticate = function(id, password, callback) {
  var users = {
    jason: {
      password: '1234',
      tenantId: 'dep01'
    },
    john: {
      password: '5678',
      tenantId: 'dep01'
    },
    mary: {
      password: '9012',
      tenantId: 'dep02'
    }
  };
  user = users[id];
  if (!user) {
    return callback(new Error("Fail to authenticate, id:" + id));
  }
  if ( user.password !== password ) {
    return callback(new Error("Fail to authenticate, id:" + id));
  }
  callback(null, user.tenantId);
};
// Export the class
module.exports = ExampleLocalAuth;
