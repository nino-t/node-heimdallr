const Misty = require('@supersoccer/misty')

const $ = Misty.Config
const t = Misty.Tools
const _ = require('lodash')
const request = require('request')

const Cache = Misty.Yggdrasil
const Driver = Misty.Dwarfs
const cache = new Cache($.app.name)


class Heimdallr {
  constructor () {
    this.passport = this.passport.bind(this)
    this.token = this.token.bind(this)
    this.identity = this.identity.bind(this)
    this.access = this.access.bind(this)
    this.authUrl = this.getAuthUrl()
  }

  /**
   * Validate user's authorization
   * @param {middleware}
   */
  passport (req, res, next) {
    // hitch
    res.locals.app = $.app

    if ($.heimdallr.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    const accessToken = req.cookies[$.heimdallr.cookie]

    if (_.isUndefined(accessToken)) {
      return res.redirect($.app.loginUrl)
      // return res.redirect(this.authUrl)
    }
    // Store access token widely during runtime
    res.locals.accessToken = accessToken

    const key = this.key(res, 'session')

    cache.get(key, true).then(identity => {
      if (_.isNull(identity)) {
        return res.redirect($.app.loginUrl)
      }

      res.locals.sessionKey = this.key(res, 'session')
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

  key (res, prefix) {
    const at = t.accessToken(res)
    const key = at.slice(0, 4) + at.slice(Math.floor(at.length / 2), Math.floor(at.length / 2) + 4) + at.slice(-4)
    return `${prefix}:${key}`
  }

  token (req, res, next) {
    if (_.isUndefined(req.query.code)) {
      res.status(403)
      return res.send('[74001] Access forbidden.')
    }

    request.post({
      url: $.heimdallr.token,
      json: {
        app_key: $.app.appKey,
        app_secret: $.app.appSecret,
        grant_type: 'authorization_code',
        redirect_uri: $.heimdallr.callback,
        code: req.query.code
      }
    }, (err, _res, body) => {
      if (!err && _res.statusCode === 200) {
        res.cookie($.heimdallr.cookie, body.access_token)
        // Continue to identity middleware
        res.locals.accessToken = body.access_token
        next()
      } else {
        res.status(403)
        res.send('[74004] Access forbidden.')
      }
    })
  }

  identity (req, res, next) {
    request.get({
      url: $.heimdallr.identity,
      headers: {
        Authorization: t.authHeader(res)
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
          token: t.accessToken(res)
        }

        const key = this.key(res, 'session')

        cache.set(key, identity)
        res.locals.identity = identity
        next()
      } else {
        res.status(403)
        return res.send('[74006] Access forbidden.')
      }
    })
  }

  access (req, res, next) {
    if ($.heimdallr.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    Driver.get({
      app: $.app.name,
      key: this.key(res, 'iam-raw'),
      query: {
        sql: 'SELECT * FROM iam WHERE user_id = ? AND deleted_at IS NULL',
        values: [
          res.locals.identity.userId
        ]
      }
    }).then(rawIAM => {
      return this.parseIAM(rawIAM, res)
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

        for (let role of $.heimdallr.roles) {
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

  session (req, res, next) {
    next()
  }

  parseIAM (rawIAM, res) {
    if (_.isUndefined(rawIAM)) {
      return Promise.resolve()
    }

    return new Promise((resolve, reject) => {
      const key = this.key(res, 'iam')

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

              const names = $.iam.roles
              const binary = t.getAccessBinary(moduleAccess)
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

  getAuthUrl () {
    const qs = {
      app_key: $.app.appKey,
      response_type: 'code',
      redirect_uri: $.heimdallr.callback,
      scope: $.heimdallr.scope.AUTH__USERS__USERS_PROFILE_READ,
      state: $.heimdallr.state
    }

    return t.url($.heimdallr.auth, qs)
  }
}

module.exports = new Heimdallr()
