const { Config, Utils, Yggdrasil, Dwarfs } = require('@supersoccer/misty-loader')
const _ = Utils.Lodash
const request = require('request')
const cache = new Yggdrasil(Config.App.name)

class Heimdallr {
  static get authUrl () {
    return Heimdallr.getAuthUrl()
  }

  static authHeader (res) {
    return `Bearer ${res.locals.accessToken}`
  }

  static accessToken (res) {
    return res.locals.accessToken
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

    if (Config.Heimdallr.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    const accessToken = req.cookies[Config.Heimdallr.cookie]

    if (_.isUndefined(accessToken)) {
      return res.redirect(Config.Heimdallr.login)
      // return res.redirect(Heimdallr.authUrl)
    }
    // Store access token widely during runtime
    res.locals.accessToken = accessToken

    const key = Heimdallr.key(res, 'session')

    cache.get(key, true).then(identity => {
      if (_.isNull(identity)) {
        return res.redirect(Config.Heimdallr.login)
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

  static key (res, prefix) {
    const at = Heimdallr.accessToken(res)
    const key = at.slice(0, 4) + at.slice(Math.floor(at.length / 2), Math.floor(at.length / 2) + 4) + at.slice(-4)
    return `${prefix}:${key}`
  }

  static token (req, res, next) {
    if (_.isUndefined(req.query.code)) {
      res.status(403)
      return res.send('[74001] Access forbidden.')
    }

    request.post({
      url: Config.Heimdallr.token,
      json: {
        app_key: Config.Heimdallr.key,
        app_secret: Config.Heimdallr.secret,
        grant_type: 'authorization_code',
        redirect_uri: Config.Heimdallr.callback,
        code: req.query.code
      }
    }, (err, _res, body) => {
      if (!err && _res.statusCode === 200) {
        res.cookie(Config.Heimdallr.cookie, body.access_token)
        // Continue to identity middleware
        res.locals.accessToken = body.access_token
        next()
      } else {
        res.status(403)
        res.send('[74004] Access forbidden.')
      }
    })
  }

  static identity (req, res, next) {
    request.get({
      url: Config.Heimdallr.identity,
      headers: {
        Authorization: Heimdallr.authHeader(res)
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
          token: Heimdallr.accessToken(res)
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
    if (Config.Heimdallr.whitelist.indexOf(req.path) >= 0) {
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

      const moduleId = res.locals.module.id
      const _IAM = {}
      _IAM.roles = []
      _IAM.role = {}
      _IAM.apps = []

      if (IAM.superuser) {
        _IAM.superuser = IAM.superuser
        _IAM.apps = res.locals.apps

        for (let role of Config.IAM.roles) {
          _IAM.role[role] = true
        }

        _IAM.permission = 15
      } else {
        const _roles = _.find(IAM.access, { appId: res.locals.appId })
        if (_roles) {
          _IAM.roles = _roles.modules

          const _role = _.find(_IAM.roles, { moduleId: moduleId })
          if (_role) {
            _IAM.permission = _role.roles.permission
            _IAM.role = _role.roles
            delete _IAM.role.permission
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
            email: identity.email
          },
          superuser: identity.superuser === 1,
          access: []
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
              const binary = Heimdallr.getAccessBinary(moduleAccess)
              const binaries = binary.split('')

              for (let i in names) {
                acl.roles[names[i]] = parseInt(binaries[i]) === 1
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

  static getAuthUrl () {
    const qs = {
      app_key: Config.Heimdallr.key,
      response_type: 'code',
      redirect_uri: Config.Heimdallr.callback,
      scope: Config.Heimdallr.scope.AUTH__USERS__USERS_PROFILE_READ,
      state: Config.Heimdallr.state
    }

    return Utils.url.build(Config.Heimdallr.auth, qs)
  }
}

module.exports = Heimdallr
