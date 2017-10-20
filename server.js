//server.js
// Fake ADFS
// WS-Federation IDP
// Michael Coleman
//
// Some things are hardcoded for testing purposes while i develop and test.

var path = require('path')
var jsonQuery = require('json-query')
var config = require('read-config')(path.join(__dirname, 'config.json'))
var queryString = require('querystring')
var fs = require('fs')
var moment = require('moment')
var url = require('url')
var passport = require('passport')
var LocalStrategy = require('passport-local').Strategy;
var db = require('./db');

var timeout = config.federation.timeout

// Federation Values
var wsfedIssuer = config.federation.issuer

var SigningCert = fs.readFileSync(path.join(__dirname, config.federation.certs.tokensigningcert))
var SigningKey = fs.readFileSync(path.join(__dirname, config.federation.certs.tokensigningkey))

// Server Cert / Key
var serverCert = fs.readFileSync(path.join(__dirname, config.server.cert))
var serverKey = fs.readFileSync(path.join(__dirname, config.server.key))
var secureOptions = {key: serverKey, cert: serverCert};

var express = require('express')
var session = require('express-session')({
  secret: config.session.secret,
  name:  config.session.name,
  resave: true,
  saveUninitialized: false,
  unset: 'destroy'
})

var wsfed = require('./templates').WSFed
var sts = require('./templates').STS

var app = express()
var server = require('https').createServer(secureOptions, app)


// Configure the local strategy for use by Passport.
//
// The local strategy require a `verify` function which receives the credentials
// (`username` and `password`) submitted by the user.  The function must verify
// that the password is correct and then invoke `cb` with a user object, which
// will be set at `req.user` in route handlers after authentication.
passport.use(new LocalStrategy(
  function(username, password, cb) {
    db.users.findByUsername(username, function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      if (user.password != password) { return cb(null, false); }
      return cb(null, user);
    });
  }));

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  The
// typical implementation of this is as simple as supplying the user ID when
// serializing, and querying the user record by ID from the database when
// deserializing.

passport.serializeUser(function(user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function(id, cb) {
  db.users.findById(id, function (err, user) {
    if (err) { return cb(err); }
    cb(null, user);
  });
});

// Express
app.use(session)
app.use(require('morgan')('combined'))
app.use(require('cookie-parser')())
app.use(require('body-parser').json())
app.use(require('body-parser').urlencoded({ extended: true }))

app.use(passport.initialize())
app.use(passport.session())

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.disable('x-powered-by')

// Static Files
app.use(express.static(path.join(__dirname, '/server')))

app.get('/', function (req, res) {
  res.redirect(302, '/login');
})

// Act as STS Metadata Provider
app.get('/federationmetadata/2007-06/federationmetadata.xml', function (req, res) {
  console.log('metadata')
  // generate Metadata
})

//  Act as ADFS Metadata Provider
app.get('/adfs/fs/federationserverservice.asmx', function (req, res) {
  console.log('metadata')
  // generate Metadata
})

// Act as Login Provider
app.get('/login', function (req, res) {
  //  WIF applications will do a passive redirect to STS to auth.
  res.sendFile(path.join(__dirname, '/server/index.html'));
})

app.post('/login', passport.authenticate('local', {
    failureRedirect: '/login' }),
  function(req, res) {
  var refererUri = req.headers.referer
  if (!refererUri) {
    // IDP initiated, need to see what apps are available, check endpoints in config!
    res.redirect('/apps')
  } else {
    // SP Initiated, redirect back to requester!
    console.log('[SP Initiated! Let it flow!]')
    var contexturi = url.parse(refererUri, true)
    var refererWa = contexturi.query.wa
    var refererWctx = contexturi.query.wctx
    var refererWtRealm = contexturi.query.wtrealm
    res.redirect('/adfs/ls/?wa=' + refererWa + '&wctx=' + refererWctx + '&wtrealm=' + refererWtRealm);
  }
})

app.get('/apps', function (req, res) {
  res.render('home', { user: req.user });
})

app.get('/profile', require('connect-ensure-login').ensureLoggedIn(),
  function(req, res){
    res.render('profile', { user: req.user });
})

app.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/login');
})

// Act as ADFS oAuth
app.get('/adfs/oauth2', function (req, res) {
  // ADSF OAUTH
})

// Act as WS-Trust Provider
app.get('/adfs/services/trust/2005/:authtype', function (req, res) {
  // add authentication types to configuration file...  add in passport strategies for required strategies
  console.log('trust/auth: ' + req.params.authtype)
  // Path can determine Auth Type, I dont want to code all of these so will have to pick a few important ones.
  //  /adfs/services/trust/2005/windowstransport
  //  /adfs/services/trust/2005/certificatemixed
  //  /adfs/services/trust/2005/certificatetransport
  //  /adfs/services/trust/2005/usernamemixed
  //  /adfs/services/trust/2005/kerberosmixed
  //  /adfs/services/trust/2005/issuedtoken*
})

// Act as WS-Federation Provider
app.get('/adfs/ls/\*', function (req, res) {
  if (!req.query) {
    var adfsreferer = req.headers.referer || rreq.protocol + '://' + req.get('host') + req.originalUrl
    res.redirect(302, '/login?wctx=' + adfsreferer)
  } else {

  //  Wctx: This is some session data that the application wants sent back to
  //  it after the user authenticates.
  //  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
  //  Wtrealm: This tells ADFS what application I was trying to get to.
  //  This has to match the identifier of one of the relying party trusts
  //  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it
  //  here.

  /* If incoming request is IDP initiated, the Querystrings will not
       be populated, so lets check, and if undefined, populate with static
       IDP config vars.
       */
  var wa = req.query.wa
  if (typeof wa === 'undefined') {
    wa = config.federation.idp.wa
  }
  var wctx = req.query.wctx
  if (typeof wctx === 'undefined') {
    wctx = config.federation.idp.wctx
  }
  var wtrealm = req.query.wtrealm
  if (typeof wtrealm === 'undefined') {
    wtrealm = config.federation.idp.wtrealm
  }
  var relyingpartners = config.federation
  var EndPointfilter = jsonQuery('relyingpartners[name=' + wtrealm + '].options.endpoints.url', { data: relyingpartners})
  var endPoint = EndPointfilter.value

    /* Generate WSFed Assertion.  These attributes are
       configured previously in the code.
       cert: this is the cert used for encryption
       key: this is the key used for the cert
       issuer: the assertion issuer
       lifetimeInSeconds: timeout
       audiences: this is the application ID for sharepoint, urn:sharepoint:webapp
       attributes:  these should map to the mappings created for the IDP in SharePoint
       */

  var wsfed_options = {
    wsaAddress: wtrealm,
    cert: SigningCert,
    key: SigningKey,
    issuer: wsfedIssuer,
    lifetimeInSeconds: timeout,
    audiences: wtrealm,
    attributes: {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': req.user.emails[0].value,
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': req.user.username,
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': req.user.name.givenName,
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/userdata': req.user.displayName,
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': req.user.familyName
    }
  }

    /* Sign the Assertion */
  var signedAssertion = wsfed.create(wsfed_options)
  // res.set('Content-Type', 'text/xml')
  //res.send(signedAssertion)
  res.render('working', { endpoint: endPoint, wa: wa, wresult: signedAssertion, wctx: wctx})
 }
})

// Express error handling
app.use(function (req, res) {
  res.status(404).send("Sorry can't find that!")
})

app.use(function (err, req, res) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

//  This may or may not be needed, they arent populated with actual values, but
//  have not tested WITHOUT yet.
//
//  MSISAuth and MSISAuth1 are the encrypted cookies used to validate the SAML
//  assertion produced for the client. These are what we call the "authentication
//  cookies", and you will see these cookies ONLY when AD FS 2.0 is the IDP.
//  Without these, the client will not experience SSO when AD FS 2.0 is the IDP.
//
//  MSISAuthenticated contains a base64-encoded timestamp value for when the client
//  was authenticated. You will see this cookie set whether AD FS 2.0 is the IDP
//  or not.
//
//  MSISSignout is used to keep track of the IDP and all RPs visited for the SSO
//  session. This cookie is utilized when a WS-Federation sign-out is invoked.
//  You can see the contents of this cookie using a base64 decoder.
//  MSISLoopDetectionCookie is used by the AD FS 2.0 infinite loop detection
//  mechanism to stop clients who have ended up in an infinite redirection loop
//  to the Federation Server. For example, if an RP is having an issue where it
//  cannot consume the SAML assertion from AD FS, the RP may continuously redirect
//  the client to the AD FS 2.0 server. When the redirect loop hits a certain
//  threshold, AD FS 2.0 uses this cookie to detect that threshold being met,
//  and will throw an exception which lands the user on the AD FS 2.0 error page
//  rather than leaving them in the loop. The cookie data is a timestamp that is
//  base64 encoded.
//
//    HTTP::cookie insert name "MSISAuth" value "ABCD" path "/adfs"
//    HTTP::cookie insert name "MSISSignOut" value "ABCD" path "/adfs"
//    HTTP::cookie insert name "MSISAuthenticated" value "ABCD" path "/adfs"
//    HTTP::cookie insert name "MSISLoopDetectionCookie" value "ABCD" path "/adfs"

module.exports = {server: server, config: config}
