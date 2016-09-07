#!/usr/bin/env node
var AWS               = require('aws-sdk');
var http              = require('http');
var httpProxy         = require('http-proxy');
var express           = require('express');
var bodyParser        = require('body-parser');
var PassThroughStream = require('stream').PassThrough;
var Readable          = require('stream').Readable;
var figlet            = require('figlet');
var basicAuth         = require('basic-auth');
var session           = require('express-session');
var url               = require('url');
var util              = require('util');
var Auth              = require('./lib/auth');
var fs                = require('fs');
var path              = require('path');
var Logger            = require('bunyan');
var createCWStream    = require('bunyan-cloudwatch');
var ipaddr            = require('ipaddr.js');
var os                = require('os');
var path              = require('path');
var sts               = new AWS.STS();
var debug             = true;

// Command line input parameter
var yargs = require('yargs')
  .usage('usage: $0 <aws-es-cluster-endpoint> [options]')
  .option('a', {
    alias    : 'auth-classname',
    default  : 'exampleLocalAuth',
    demand   : false,
    describe : 'the name of authentication class',
    type     : 'string'
  })
  .option('b', {
    alias    : 'bind-address',
    default  : '127.0.0.1',
    demand   : false,
    describe : 'the ip address to bind to',
    type     : 'string'
  })
  .option('n', {
    alias    : 'proxy-name',
    default  : 'aws-mt-kibana',
    demand   : true,
    describe : 'the name of kibana proxy',
    type     : 'string'
  })
  .option('p', {
    alias    : 'port',
    default  : 80,
    demand   : false,
    describe : 'the port to bind to',
    type     : 'number'
  })
  .option('r', {
    alias    : 'region',
    demand   : false,
    describe : 'the region of the Elasticsearch cluster',
    type     : 'string'
  })
  .help()
  .version()
  .strict();
var argv = yargs.argv;

if (argv._.length !== 1) {
  yargs.showHelp();
  process.exit(1);
}

var ENDPOINT = argv._[0];
// Try to infer the region if it is not provided as an argument.
var REGION = argv.r;
if (!REGION) {
  var m = ENDPOINT.match(/\.([^.]+)\.es\.amazonaws\.com\.?$/);
  if (m) {
    REGION = m[1];
  } else {
    console.error('region cannot be parsed from endpoint address, etiher the endpoint must end ' +
      'in .<region>.es.amazonaws.com or --region should be provided as an argument');
    yargs.showHelp();
    process.exit(1);
  }
}

var TARGET = argv._[0];
if (!TARGET.match(/^https?:\/\//)) {
  TARGET = 'https://' + TARGET;
}

var PROXY_NAME  = argv.n;
if (!PROXY_NAME.match(/^[\.\-_\/#A-Za-z0-9]+$/)) {
  console.error('proxy name must satisfy regular expression pattern : [\\.\\-_/#A-Za-z0-9]+');
  yargs.showHelp();
  process.exit(1);
}

var BIND_ADDRESS   = argv.b;
var PORT           = argv.p;
var AUTH_API_NAME  = argv.a;

// Load authentication module
var authStrategy    = require('./lib/'+ AUTH_API_NAME);

// Create AWS cloudwatch logger
var stream = createCWStream({
  logGroupName          : util.format('es-kibana-proxy-access-log/%s', PROXY_NAME),
  logStreamName         : os.hostname(),
  cloudWatchLogsOptions : {
    region              : REGION
  }
});

function reqSerializer(req) {
  var address = req.connection.remoteAddress;
  var ip = address.replace(/^.*:/, '');
  var xForwardedFor = req.headers["X-Forwarded-For"];
  if(!xForwardedFor) xForwardedFor = null;
  return {
    method            : req.method,
    url               : req.url,
    headers           : req.headers,
    remoteAddress     : ip,
    "x-forwarded-for" : xForwardedFor
  };
}

var log = new Logger({
  name    : 'index',
  streams : [
    {
      stream : stream,
      type   : 'raw',
      level  : 'info'
    }
  ],
  serializers: {
    req: reqSerializer,
    res: Logger.stdSerializers.res
  }
});

function getAWSAccountId(req, res, next) {
  if(!req.session.awsAccountId) {
    sts.getCallerIdentity({}, function(err, data) {
      if (err) {
        console.log(err, err.stack); // an error occurred
      }
      else {
        if (err) {
          if(debug) console.log('Error: get aws accountId failed.', err);
          log.error({'req': req, 'res': res, 'action': 'get aws accountId', 'timestamp': timestamp}, err);
        }
        else {
          req.session.awsAccountId = data.Account;
        }
        return next();
      }
    });
  } else {
    return  next();
  }
}
/*
 * User Authentication
 */
function login(req, res, next) {
  function unauthorized(res) {
    res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
    return res.sendStatus(401);
  }
  var sess  = req.session;
  var user  = basicAuth(req);  // get user info from request header authorization
  if(!sess.status || sess.initial) {  // session empty or expired 
    // prompt login panel when empty user or session expired
    if (!user || !user.name || !user.pass || !sess.status) {
      // return unauth if empty user info or session expired
      sess.status  = 'active'; // status variable was used to re-authorize when session expired
      sess.initial = true;  // initial variable was used to stop authentication if user ever login last hour
      return unauthorized(res);
    }
    // get aws temporary credential and assign to session
    var timestamp = new Date().toISOString();
    getCredential(user.name, user.pass, sess.awsAccountId, function(err, data){
      var receiveTime = new Date();
      var elapsedTime = receiveTime - new Date(timestamp);
      if (err) {
        res.statusCode = 401;
        log.warn({'req': req, 'res': res, 'id': user.name, 'tenantId': null, 'action': 'login', 'timestamp': timestamp, 'elapasedTime': elapsedTime}, err);
        return unauthorized(res);
      } else {
        log.info({'req': req, 'res': res, 'id': user.name, 'tenantId': data.tenantId, 'action': 'login', 'timestamp': timestamp, 'elapasedTime': elapsedTime});
        sess.tenantId        = data.tenantId;
        sess.accessKeyId     = data.AccessKeyId;
        sess.secretAccessKey = data.SecretAccessKey;
        sess.sessionToken    = data.SessionToken;
        sess.expireTime      = data.Expiration;
        sess.user            = user;
        sess.host            = req.headers.host;
        delete sess.initial;
        return next();
      }
    });
  } else {
    return next();
  }
}

/*
 * Get login credential via assume role
 */
function getCredential(id, password, awsAccountId, callback) {
  var auth = new Auth(authStrategy);
  auth.verify(id, password, function(err, data){
    if (err) {
      if(debug) console.log('Error: Authentication failed. ID:', id, err);
      return callback(err);
    }
    else {
      if(debug) console.log('Authentication successfully. ID:', id);
      var tenantId = data;
      var assumeRoleARN = util.format("arn:aws:iam::%s:role/%s", awsAccountId, util.format("%s-%s", PROXY_NAME , tenantId));
      var params = {
        RoleArn: assumeRoleARN, /* required */
        RoleSessionName: 'getCredential' /* required */
      };
      sts.assumeRole(params, function (err, data) {
        if (err) {
          if(debug) console.log('Error: Assume role failed:', err);
          return callback(err);
        }
        else {
          if(debug) console.log('Assume role successfully. Role ARN:', assumeRoleARN);
          data.Credentials.tenantId = tenantId;
          return callback(null, data.Credentials);
        }
      });
    }
  });
}

/*
 * Generate AWS credential
 */
var creds;
function genCreds(req, res, next) {
  var options = {
    accessKeyId     : req.session.accessKeyId,
    secretAccessKey : req.session.secretAccessKey,
    sessionToken    : req.session.sessionToken,
    expireTime      : req.session.expiration
  };
  creds = new AWS.Credentials(options);
  return creds.get(function (err) {
    if (err) return next(err);
    else return next();
  });
}

/*
 * Node.js middleware
 */
var app = express();
app.use(session({ secret: 'es-kibana proxy', cookie: { maxAge: 3600000 }, resave: true, saveUninitialized: true}));
app.use(getAWSAccountId);
app.use(login);
app.use(bodyParser.raw({type: '*/*'}));
app.use(genCreds);

// proxy request to elasticsearch
var proxy = httpProxy.createProxyServer({
  target: TARGET,
  changeOrigin: true,
  secure: true
});

app.use(function (req, res) {
  var pathname = url.parse(req.url).pathname;
  if(pathname == '/') {
    // redirect of root url
    return res.redirect('/_plugin/kibana/');
  } else if(pathname.indexOf('.kibana-4') > -1 && pathname.indexOf('/field/_source') > -1) {
    // special case: kibana code written in hard code way to read .kibana-4, so this api won't return user-customized kibana index
    return res.json(JSON.parse('{".kibana-4":{"mappings":{"index-pattern":{"_source":{"full_name":"_source","mapping":{}}},"config":{"_source":{"full_name":"_source","mapping":{}}}}}}'));
  } else if(pathname.indexOf('.kibana-4') > -1) {
    // exchange default kibana index to user-customized kibana index
    var sess  = req.session;
    req.url = req.url.replace( /\/.kibana-4[^\/]*/g ,'/.kibana-4-' + sess.tenantId);
  }
  var bufferStream;
  if (Buffer.isBuffer(req.body)) {
    bufferStream = new PassThroughStream();
    bufferStream.end(req.body);
  }
  proxy.web(req, res, {buffer: bufferStream});
});

// add aws signature to authorization header when start to proxy request
proxy.on('proxyReq', function (proxyReq, req, res, options) {
  var endpoint   = new AWS.Endpoint(ENDPOINT);
  var request    = new AWS.HttpRequest(endpoint);
  request.method = proxyReq.method;
  request.path   = proxyReq.path;
  request.region = REGION;

  if (Buffer.isBuffer(req.body)) request.body = req.body;
  if (!request.headers) request.headers = {};
  request.headers['presigned-expires'] = false;
  request.headers['Host'] = ENDPOINT;

  var signer = new AWS.Signers.V4(request, 'es');
  signer.addAuthorization(creds, new Date());
  proxyReq.setHeader('Host', request.headers['Host']);
  proxyReq.setHeader('X-Amz-Date', request.headers['X-Amz-Date']);
  proxyReq.setHeader('Authorization', request.headers['Authorization']);
  if (request.headers['x-amz-security-token']) proxyReq.setHeader('x-amz-security-token', request.headers['x-amz-security-token']);
  var sess      = req.session;
  var timestamp = new Date().toISOString();
  log.info({'req': req, 'res': res, 'id': sess.user.name, 'tenantId': sess.tenantId, 'action': 'proxy', 'timestamp': timestamp});
});

// start to listen port
http.createServer(app).listen(PORT);

console.log(figlet.textSync('AWS ES Proxy!', {
  font             : 'Speed',
  horizontalLayout : 'default',
  verticalLayout   : 'default'
}));

console.log('AWS ES cluster available at http://' + BIND_ADDRESS + ':' + PORT);
console.log('Kibana available at http://' + BIND_ADDRESS + ':' + PORT + '/_plugin/kibana/');
