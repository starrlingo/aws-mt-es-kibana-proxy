// Constructor
function Auth(authSerice) {
  // always initialize all instance properties
  this._authSerice     = authSerice; // default value
}

Auth.prototype.verify = function(id, password, callback) {
  if(id && password) {
    this._authSerice.authenticate(id, password, function(err, tenantId){
      if(err) {
        callback(err);
      } else {
        if(tenantId) {
          callback(null, tenantId);
        } else {
          // Return user id if no tenantId return
          callback(null, id);
        }
      }
    });
  } else {
    callback(new Error("Empty id or password"));
  }
};

// export the class
module.exports = Auth;
