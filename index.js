// index.js

// 'use strict'

var config = require('./server').config
var server = require('./server').server

server.listen({host: config.server.ip, port: config.server.port || 443}, function() {
  console.log('FakeADFS listening at ' + config.server.ip + ':' + config.server.port + '...')
})

server.on('error', function(err) {
if (err.code === 'EADDRINUSE') {
    config.listen.port++
    console.warn('Address in use, retrying on port ' + config.listen.port)
    setTimeout(function () {
      server.listen(config.listen.port)
    }, 250)
  } else {
    console.log('server.listen ERROR: ' + err.code)
  }
})
