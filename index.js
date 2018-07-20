const $ = require('config')
const _ = require('lodash')
const t = require('@supersoccer/tools')
const template = require('@supersoccer/template')
const request = require('request')

const Cache = require('@supersoccer/yggdrasil')
const Driver = require('@supersoccer/dwarfs')
const cache = new Cache($.cache.app.misty)

const tpl = {
  login: template.load('accounts/login'),
  oauth: template.load('accounts/oauth'),
  profile: template.load('accounts/profile')
}

class Heimdallr {
  constructor () {
    this.passport = this.passport.bind(this)
    this.token = this.token.bind(this)
    this.identity = this.identity.bind(this)
    this.access = this.access.bind(this)
    this.index = this.index.bind(this)
    this.login = this.login.bind(this)
    this.oauth = this.oauth.bind(this)
    this.logout = this.logout.bind(this)

    this.authUrl = this.getAuthUrl()
  }

  /**
   * Validate user's authorization
   * @param {middleware}
   */
  passport (req, res, next) {
    // hitch
    res.locals.app = $.app

    if ($.passport.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    const accessToken = req.cookies[$.auth.cookie]

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
      url: $.auth.host.token,
      json: {
        app_key: $.app.appKey,
        app_secret: $.app.appSecret,
        grant_type: 'authorization_code',
        redirect_uri: $.auth.callback,
        code: req.query.code
      }
    }, (err, _res, body) => {
      if (!err && _res.statusCode === 200) {
        res.cookie($.auth.cookie, body.access_token)
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
      url: $.auth.host.identity,
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
    if ($.passport.whitelist.indexOf(req.path) >= 0) {
      return next()
    }

    Driver.get({
      app: 'Misty',
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
      _IAM.projects = []

      if (IAM.superuser) {
        _IAM.superuser = IAM.superuser
        _IAM.projects = res.locals.projects

        for (let role of $.iam.roles) {
          _IAM.role[role] = true
        }

        _IAM.permission = 15
      } else {
        const _roles = _.find(IAM.access, { projectId: res.locals.projectId })
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
            for (let projectAccess of IAM.access) {
              const project = _.find(res.locals.projects, { identifier: projectAccess.projectId })

              if (project) {
                _IAM.projects.push(project)
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
          const projectId = _IAM.project_id
          let access

          try {
            access = JSON.parse(_IAM.access)
          } catch (e) {}

          if (access.length > 0) {
            const accessTmp = {
              projectId: projectId,
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
      redirect_uri: $.auth.callback,
      scope: $.auth.scope.USERS__USERS_PROFILE_READ,
      state: $.auth.state
    }

    return t.url($.auth.host.oauth, qs)
  }

  index (req, res, next) {
    res.sendStatus(200)
  }

  oauth (req, res, next) {
    // res.redirect($.app.hostname)
    res.marko(tpl.oauth)
  }

  login (req, res, next) {
    res.marko(tpl.login, {
      authUrl: this.authUrl
    })
  }

  logout (req, res, next) {
    res.clearCookie($.auth.cookie)
    cache.del(this.key(res, 'session'))
    res.redirect($.app.hostname)
  }

  profile (req, res, next) {
    res.marko(tpl.profile)
  }
}

module.exports = new Heimdallr()
