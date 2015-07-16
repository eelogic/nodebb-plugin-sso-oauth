(function(module) {

  'use strict';

  var User = module.parent.require('./user');
  var Groups = module.parent.require('./groups');
  var meta = module.parent.require('./meta');
  var db = module.parent.require('../src/database');
  var passport = module.parent.require('passport');
  var fs = module.parent.require('fs');
  var path = module.parent.require('path');
  var nconf = module.parent.require('nconf');
  var winston = module.parent.require('winston');
  var async = module.parent.require('async');

  /*
     constants are configured at project plugin_config path so you can customize it
     {
       type: 'oauth2',
       name: 'youname',
       scope: 'read',
       reource_uri: 'https://bbs.yourdomain.com/auth/yourname/callback',
       oauth2: {
         authorizationURL: 'http://www.yourdomain.com/oauth2/authorize',
         tokenURL: 'http://www.yourdomain.com/oauth2/access_token',
         clientID: '',
         clientSecret: ''
       },
       userRoute: 'http://www.yourdomain.com/oauth2/yourpath',
       iconClass: 'yourlogo'
     }
  */
  var constants = module.parent.require('../plugin_configs/sso_qingcloud_constants');

  var configOk = false;
  var InternalOAuthError = require('passport-oauth').InternalOAuthError;
  var OAuth = {};
  var PassportOAuth, opts;

  // jscs:disable maximumLineLength
  if(!constants.name) {
    winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
  } else if(!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
    winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
  } else if(!constants.userRoute) {
    winston.error('[sso-oauth] User Route required (library.js:31)');
  } else {
    configOk = true;
  }

  // jscs:disable disallowDanglingUnderscores
  OAuth.getStrategy = function(strategies, callback) {
    if(configOk) {
      var strategy = constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy';
      PassportOAuth = require('passport-oauth')[strategy];

      if(constants.type === 'oauth') {
        // options OAuth
        opts = constants.oauth;
        opts.callbackURL = constants.resource_uri;

        PassportOAuth.Strategy.prototype.userProfile = function(token, secret, params, done) {
          this._oauth.get(constants.userRoute, token, secret, function(err, body, res) {
            if(err) {
              return done(new InternalOAuthError('failed to fetch user profile', err));
            }

            try {
              var json = JSON.parse(body);
              OAuth.parseUserReturn(json, function(err, profile) {
                if(err) {
                  return done(err);
                }
                profile.provider = constants.name;
                done(null, profile);
              });
            } catch(e) {
              done(e);
            }
          });
        };
      } else if(constants.type === 'oauth2') {
        // options OAuth2
        opts = constants.oauth2;
        opts.callbackURL = constants.resource_uri;

        PassportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
          this._oauth2.get(constants.userRoute, accessToken, function(err, body, res) {
            if(err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

            try {
              var json = JSON.parse(body);
              OAuth.parseUserReturn(json, function(err, profile) {
                if(err) {
                  return done(err);
                }
                profile.provider = constants.name;
                done(null, profile);
              });
            } catch(e) {
              done(e);
            }
          });
        };
      }

      passport.use(constants.name, new PassportOAuth(opts, function(token, secret, profile, done) {
        OAuth.login({
          oAuthid: profile.id,
          handle: profile.displayName,
          email: profile.emails[0].value,
          isAdmin: profile.isAdmin
        }, function(err, user) {
          if(err) {
            return done(err);
          }
          done(null, user);
        });
      }));

      strategies.push({
        name: constants.name,
        url: '/auth/' + constants.name,
        callbackURL: '/auth/' + constants.name + '/callback',
        icon: constants.iconClass,
        scope: (constants.scope || '').split(',')
      });

      callback(null, strategies);
    } else {
      callback(new Error('OAuth Configuration is invalid'));
    }
  };

  // jscs:enable disallowDanglingUnderscores
  OAuth.parseUserReturn = function(data, callback) {
    // alter this section to include whatever data is necessary
    // nodeBB *requires* the following: id, displayName, emails.
    // everything else is optional.

    // find out what is available by uncommenting this line:

    var profile = {};
    profile.id = data.user_id;
    profile.displayName = data.user_name;
    profile.emails = [{value: data.email}];
    profile.gravatar_url = data.gravatar_url;

    // do you want to automatically make somebody an admin? This line might help you do that...
    // profile.isAdmin = data.isAdmin ? true : false;

    // delete or comment out the next TWO (2) lines when you are ready to proceed
    // process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
    // return callback(new Error('Congrats! So far so good -- please see server log for details'));

    callback(null, profile);
  },

  OAuth.requireInvitation = function(email, callback) {
    callback(true);
  },

  OAuth.login = function(payload, callback) {
    OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
      if(err) {
        return callback(err);
      }

      if(uid !== null) {
        // existing User
        callback(null, {
          uid: uid
        });
      } else {
        // new User
        var success = function(uid) {
          // save provider-specific information to the user
          User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
          db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

          if(payload.isAdmin) {
            Groups.join('administrators', uid, function(err) {
              callback(null, {
                uid: uid
              });
            });
          } else {
            callback(null, {
              uid: uid
            });
          }
        };

        User.getUidByEmail(payload.email, function(err, uid) {
          if(err) {
            return callback(err);
          }

          if(!uid) {
            User.create({
              username: payload.handle,
              email: payload.email
            }, function(err, uid) {
              if(err) {
                return callback(err);
              }

              success(uid);
            });
          } else {
            success(uid); // existing account -- merge
          }
        });
      }
    });
  };

  OAuth.getUidByOAuthid = function(oAuthid, callback) {
    db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
      if(err) {
        return callback(err);
      }
      callback(null, uid);
    });
  };

  OAuth.deleteUserData = function(uid, callback) {
    async.waterfall([
      async.apply(User.getUserField, uid, constants.name + 'Id'),
      function(oAuthIdToDelete, next) {
        db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
      }
    ], function(err) {
      if(err) {
        winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
        return callback(err);
      }
      callback(null, uid);
    });
  };

  // jscs:enable maximumLineLength
  module.exports = OAuth;

}(module));
