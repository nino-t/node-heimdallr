const { Config, Utils, Yggdrasil, Dwarfs, Log } = require('@supersoccer/misty-loader')
const jwt = require('jsonwebtoken')
const _ = Utils.Lodash
const moment = Utils.Moment
const request = require('request')
const cache = new Yggdrasil(Config.App.name)

class Heimdallr {
  static utils (req, res) {
    return {
      authHeader: Heimdallr.authHeader(res.locals.accessToken),
      accessToken: Heimdallr.accessToken(res.locals.accessToken),
      authUrl: Heimdallr.authUrl(req, res),
      loginUrl: Heimdallr.loginUrl(req, res) 
    }
  }

  static authHeader (accessToken) {
    return `Bearer ${accessToken}`
  }

  static accessToken (accessToken) {
    return accessToken
  }

  static accessBinary (n) {
    return ('0000' + (n >>> 0).toString(2)).slice(-4)
  }

  /**
   * Validate user's authorization
   * @param {middleware}
   */
  static passport (req, res, next) {
    // hitch
    res.locals.config = Config

    const __config = Heimdallr.__heimdallrConfig(req, res)
    if (__config.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    const accessToken = req.cookies[Heimdallr.cookieName(res)]

    if (_.isUndefined(accessToken)) {
      Log.debug('loginUrl', res.locals.Utils.Heimdallr.loginUrl)
      return res.redirect(res.locals.Utils.Heimdallr.loginUrl)
    }
    // Store access token widely during runtime
    res.locals.accessToken = accessToken

    const key = Heimdallr.key(res, 'session')

    cache.get(key, true).then(identity => {
      if (_.isNull(identity)) {
        return res.redirect(res.locals.Utils.Heimdallr.loginUrl)
      }

      res.locals.sessionKey = Heimdallr.key(res, 'session')
      res.locals.identity = identity
        
      next()
    }).catch(err => {
      const errMsg = '[75001] Unable to get cached session.'
      if (err) {
        console.error(errMsg)
      }
      res.status(500)
        
      res.send(errMsg)
    })
  }

  static loginUrl (req, res) {
    const __config = Heimdallr.__heimdallrConfig(req, res)
    return res.locals.Utils.Url.build(__config.login)
  }

  static key (res, prefix) {
    const at = Heimdallr.accessToken(res.locals.accessToken)
    const identity = jwt.decode(at)
    const key = at.slice(0, 4) + at.slice(Math.floor(at.length / 2), Math.floor(at.length / 2) + 4) + at.slice(-4)

    if (!_.isUndefined(identity)) {
      return `${prefix}:${identity.sub}:${key}`
    }

    return `${prefix}:${key}`
  }

  static token (req, res, next) {
    const __config = Heimdallr.__heimdallrConfig(req, res)
    if (_.isUndefined(req.query.code)) {
      res.status(403)
      return res.send('[74001] Access forbidden.')
    }

    Heimdallr.requestToken(req, res)
      .then(access_token => {
        request.post({
          url: `${__config.host}/_/v1/token/extend`,
          json: {
            app_key: __config.key,
            app_secret: __config.secret,
            access_token: access_token,
            expires_in: 432000
          },
          headers: {
            connection: 'Close'
          }
        }, (err, _res, body) => {
          if (!err && _res.statusCode === 200) {
            res.cookie(Heimdallr.cookieName(res), body.access_token)
            res.locals.accessToken = body.access_token

            next()
          } else {
            res.status(403)
            res.send('[74041] Access forbidden.')
          }
        })
      })
      .catch(err => {
        console.log('err', err)
        res.status(403)
        res.send('[74004] Access forbidden.')
      })
  }

  static identity (req, res, next) {
    const __config = Heimdallr.__heimdallrConfig(req, res)
    request.get({
      url: __config.identity,
      headers: {
        Authorization: Heimdallr.authHeader(res.locals.accessToken)
      }
    }, (err, _res, body) => {
      if (!err && _res.statusCode === 200) {
        try {
          body = JSON.parse(body)
        } catch (e) {
          res.status(403)
          return res.send('[74005] Access forbidden.')
        }

        const identity = {
          userId: body.user_id,
          firstName: body.first_name,
          lastName: body.last_name,
          email: body.email,
          token: Heimdallr.accessToken(res.locals.accessToken)
        }

        const key = Heimdallr.key(res, 'session')

        cache.set(key, identity)
        res.locals.identity = identity
        next()
      } else {
        res.status(403)
        return res.send('[74006] Access forbidden.')
      }
    })
  }

  static access (req, res, next) {
    const __config = Heimdallr.__heimdallrConfig(req, res)
    if (__config.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    Dwarfs.get({
      app: Config.App.name,
      key: Heimdallr.key(res, 'iam-raw'),
      query: {
        sql: 'SELECT * FROM iam WHERE user_id = ? AND deleted_at IS NULL',
        values: [
          res.locals.identity.userId
        ]
      }
    }).then(rawIAM => {
      return Heimdallr.parseIAM(rawIAM, res)
    }).then(IAM => {
      if (_.isUndefined(IAM)) {
        res.status(403)
        return res.send('[74002] User not found.')
      }

      let module = res.locals.module
      let moduleId = module.id

      const _IAM = {}
      _IAM.roles = []
      _IAM.role = {}
      _IAM.apps = []

      if (IAM.superuser) {
        _IAM.superuser = IAM.superuser
        _IAM.permission = 15
      }

      const _roles = _.find(IAM.access, { appId: res.locals.appId })
      if (_roles) {
        _IAM.roles = _roles.modules
        
        const _role = _.find(_IAM.roles, { moduleId: moduleId })
        if (_role) {
          _IAM.permission = _role.roles.permission
          _IAM.role = _role.roles
          // delete _IAM.role.permission
        }
      }

      if (IAM.access) {
        if (IAM.access.length > 0) {
          for (let appAccess of IAM.access) {
            const app = _.find(res.locals.apps, { identifier: appAccess.appId })

            if (app) {
              _IAM.apps.push(app)
            }
          }
        }
      }

      res.locals.IAM = _IAM
      next()
    }).catch(error => {
      console.error(error)
      res.status(400)
      res.send(`[74003] ${error}`)
    })
  }

  static session (req, res, next) {
    next()
  }

  static parseIAM (rawIAM, res) {
    const modules = res.locals.modules
    if (_.isUndefined(rawIAM)) {
      return Promise.resolve()
    }

    return new Promise((resolve, reject) => {
      const key = Heimdallr.key(res, 'iam')

      cache.get(key, true).then(IAM => {
        if (IAM) {
          return resolve(IAM)
        }

        const identity = rawIAM[0]

        IAM = {
          identity: {
            userId: identity.user_id,
            firstName: identity.first_name,
            lastName: identity.last_name,
            email: identity.email,
            logedIn_at: moment().format('YYYY-MM-DD HH:mm:ss')
          },
          superuser: identity.superuser === 1,
          access: []
        }

        if (IAM.superuser) {
          rawIAM = []
          const apps = res.locals.apps
          apps.map(app => {
            let appData = {
              app_id: app.identifier,
              access: []
            }

            JSON.parse(app.modules).map(moduleId => {
              appData.access.push([
                +(moduleId),
                15
              ])
            })

            appData.access = JSON.stringify(appData.access)
            rawIAM.push(appData)
          })
        }

        for (let _IAM of rawIAM) {
          const appId = _IAM.app_id
          let access

          try {
            access = JSON.parse(_IAM.access)
          } catch (e) {}

          if (access.length > 0) {
            const accessTmp = {
              appId: appId,
              modules: []
            }

            for (let [moduleId, moduleAccess] of access) {
              const acl = {
                moduleId: moduleId,
                roles: {}
              }

              const names = Config.IAM.roles
              const binary = Heimdallr.accessBinary(moduleAccess)
              const binaries = binary.split('')

              for (let i in names) {
                acl.roles[names[i]] = parseInt(binaries[i]) === 1

                const moduleGrouped = modules.filter(x => {
                  return x.permit && x.permit === names[i] && x.parent_id === moduleId
                })

                if (moduleGrouped) {
                  moduleGrouped.map((modField, index) => {
                    let permit = {
                      moduleId: modField.id,
                      roles: acl.roles
                    }

                    permit.roles.permission = moduleAccess
                    accessTmp.modules.push(permit)      
                  })
                }
              }

              // Store access binary
              acl.roles.permission = moduleAccess

              accessTmp.modules.push(acl)
            }

            IAM.access.push(accessTmp)
          }
        }

        cache.set(key, IAM)
        resolve(IAM)
      })
    })
  }

  static authUrl (req, res) {
    const __config = Heimdallr.__heimdallrConfig(req, res)
    const qs = {
      app_key: __config.key,
      response_type: 'code',
      redirect_uri: res.locals.Utils.Url.build(__config.callback),
      scope: __config.scope.AUTH__USERS__USERS_PROFILE_READ,
      state: __config.state
    }

    return res.locals.Utils.Url.build(__config.auth, qs)
  }

  static cookieName (res) {
    let cookieName = Config.Heimdallr.cookie 

    if (res.locals.appLock) {
      cookieName += `_${res.locals.appId}`
    }

    return cookieName
  }

  static requestToken (req, res) {
    const __config = Heimdallr.__heimdallrConfig(req, res)

    return new Promise((resolve, reject) => {
      request.post({
        url: __config.token,
        json: {
          app_key: __config.key,
          app_secret: __config.secret, 
          grant_type: 'authorization_code',
          redirect_uri: res.locals.Utils.Url.build(__config.callback),
          code: req.query.code
        },
        headers: {
          connection: 'Close'
        }
      }, (err, _res, body) => {
        if (!err && _res.statusCode === 200) {
          resolve(body.access_token)
        } else {
          reject(err)
        }
      })
    })
  }

  static __heimdallrConfig (req, res) {
    const __configHeimdallr    = Object.assign({}, Config.Heimdallr)
    let __config               = null

    let lockApp     = false
    let appSelected = null
    const __apps    = res.locals.apps
    let xURL        = null

    const headers   = req.headers
    const protocol  = req.protocol

    if (!_.isUndefined(headers['x-url'])) {
      xURL                = headers['x-url']

      const __appSelected = __apps.find(x => ((x.host).split(' ')).indexOf(xURL) >= 0)

      if (!_.isUndefined(__appSelected)) {
        lockApp           = true
        appSelected       = __appSelected.identifier
      }
    }
    
    if (lockApp) {
      const __loadConfigAPP = Config.configApplication
      if (!_.isUndefined(__loadConfigAPP[appSelected]) && !_.isUndefined(__loadConfigAPP[appSelected]['Heimdallr'])) {
        const __thisConfig  = __loadConfigAPP[appSelected].Heimdallr
        __config            = Object.assign(__configHeimdallr, __thisConfig)
        __config.login      = Config.Heimdallr.login.replace(Config.App.host, `${protocol}://${xURL}`)
        __config.auth       = Config.Heimdallr.auth.replace(Config.Heimdallr.host, __thisConfig.host)
        __config.token      = Config.Heimdallr.token.replace(Config.Heimdallr.host, __thisConfig.host)
        __config.identity   = Config.Heimdallr.identity.replace(Config.Heimdallr.host, __thisConfig.host)
        __config.callback   = Config.Heimdallr.callback.replace(Config.App.host, `${protocol}://${xURL}`)
      }
    }

    if (_.isNull(__config)) {
      __config = Config.Heimdallr
    }

    return __config
  }
}

module.exports = Heimdallr