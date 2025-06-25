/* jshint esversion: 6, asi: true, node: true */
// util.js

// private
const debug = require('debug')('WebSSH2');
const Auth = require('basic-auth');
const config = require('./config');

let defaultCredentials = { username: null, password: null, privatekey: null };

exports.setDefaultCredentials = function setDefaultCredentials({
  name: username,
  password,
  privatekey,
  overridebasic,
}) {
  defaultCredentials = { username, password, privatekey, overridebasic };
};

exports.basicAuth = function basicAuth(req, res, next) {
  const myAuth = Auth(req);
  // If Authorize: Basic header exists and the password isn't blank
  // AND config.user.overridebasic is false, extract basic credentials
  // from client]
  const { username, password, privatekey, overridebasic } = defaultCredentials;
  
  // 支持从URL查询参数获取用户名和密码（仅在配置允许时）
  if (config.options.allowUrlAuth && req.query?.username && req.query?.userpassword) {
    req.session.username = req.query.username;
    req.session.userpassword = req.query.userpassword;
    debug(`URL params auth: username=${req.query.username} and password ${req.query.userpassword ? 'exists' : 'is blank'}`);
  } else if (myAuth && myAuth.pass !== '' && !overridebasic) {
    req.session.username = myAuth.name;
    req.session.userpassword = myAuth.pass;
    debug(`myAuth.name: ${myAuth.name} and password ${myAuth.pass ? 'exists' : 'is blank'}`);
  } else {
    req.session.username = username;
    req.session.userpassword = password;
    req.session.privatekey = privatekey;
  }
  if (!req.session.userpassword && !req.session.privatekey) {
    res.statusCode = 401;
    debug('basicAuth credential request (401)');
    res.setHeader('WWW-Authenticate', 'Basic realm="WebSSH"');
    res.end('Username and password required for web SSH service.');
    return;
  }
  next();
};

// takes a string, makes it boolean (true if the string is true, false otherwise)
exports.parseBool = function parseBool(str) {
  return str.toLowerCase() === 'true';
};
