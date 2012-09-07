#!/usr/bin/env node

var express = require('express'),
    routes = require('./routes'),
    http = require('http'),
    path = require('path'),
    config = require('./lib/config');

var app = module.exports = express.createServer();

app.configure(function(){
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(app.router);
  app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
});

app.get('/', routes.index);
app.post('/create', routes.create);
app.post('/hello', routes.hello);
app.post('/exchange', routes.exchange);

if (!module.parent) {
  app.listen(config.get('server').port, function(){
    console.log("SRP server listening on port " + app.address().port);
  });
}
