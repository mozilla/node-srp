#!/usr/bin/env node

var express = require('express'),
    routes = require('./routes'),
    http = require('http'),
    path = require('path'),
    config = require('./lib/config');

var app = express();

app.configure(function(){
  app.set('port', config.get('server').port);
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
  http.createServer(app).listen(app.get('port'), function(){
    console.log("SRP server listening on port " + app.get('port'));
  });
}