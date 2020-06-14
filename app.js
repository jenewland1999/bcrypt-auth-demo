const express = require('express')
const mongoose = require('mongoose')
const session = require('client-sessions')
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs')
const csrf = require('csurf')
const app = express()

var userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: {type: String, unique: true},
  password: String
})

var User = mongoose.model('User', userSchema)

mongoose.connect('mongodb://localhost/authdb')

app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({
  cookieName: 'session',
  secret: 'uhosfez9i783wt7893394wz9zg9tgo3973w7tw373w9w9p3etzg9pt7wtoe3g9bpl8twl39ow8tgwl388t9g8l39tw39i8tiow3gt89ow3w9tw9387337wtg8928l2873t7g83ig77t273g27wg7w28tg2w78wgwz87t3g73tg2w7tlg73i2tgi37glkiuwk3etgbu3bweudfvbsyujewfgww37fgw73g',
  duration: 30 * 60 * 1000,
  activeDuration: 5 * 60 * 1000, // optional
  httpOnly: true, // Prevents JS access to the cookie
  secure: true, // Prevents setting of cookie over non-ssl (https) connections
  ephemeral: true // Deletes all cookies when the browser is closed
}))
app.use(csrf())
app.use((req, res, next) => {
  if (req.session && req.session.user) {
    User.findOne({email: req.session.user.email}, (err, user) => {
      // If a user was found, make the user available
      // TODO: Handle error
      if (user) {
        req.user = user
        delete req.user.password // Don't make the password hash available
        req.session.user = user // Update the session info
        res.locals.user = user // make the user available to templates
      }
      next()
    })
  } else {
    next() // if no session is available, do nothing
  }
})
app.set('view engine', 'pug')

function requireLogin (req, res, next) {
  // if this user isn't logged in, redirect them to
  // the login page
  if (!req.user) {
    res.redirect('/login')
  } else {
    next()
  }
}

app.get('/', (req, res) => {
  res.render('index')
})

app.post('/register', (req, res) => {
  // res.json(req.body)

  const salt = bcrypt.genSaltSync(10)
  const hash = bcrypt.hashSync(req.body.password, salt)

  var user = new User({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: hash
  })
  user.save((err) => {
    if (err) {
      var error = 'Something bad happened!'

      if (err.code === 11000) {
        error = 'That email is already taken. Please try another.'
      }

      res.render('register', {error: error})
    } else {
      res.redirect('/dashboard')
    }
  })
})

app.get('/register', (req, res) => {
  res.render('register', {csrfToken: req.csrfToken()})
})

app.post('/login', (req, res) => {
  let email = req.body.email
  User.findOne({email: email}, (err, user) => {
    if (err) {
      res.send(err)
    }
    if (!user) {
      res.render('login', {error: 'Incorrect email/password'})
    } else {
      if (bcrypt.compareSync(req.body.password, user.password)) {
        req.session.user = user
        res.redirect('/dashboard')
      } else {
        res.render('login', {error: 'Incorrect email/password.'})
      }
    }
  })
})

app.get('/login', (req, res) => {
  res.render('login', {csrfToken: req.csrfToken()})
})

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard')
})

app.listen(3000, () => {
  console.log('Server running on port 3000.')
})
