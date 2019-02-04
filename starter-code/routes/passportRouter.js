const express = require('express');

const passportRouter = express.Router();

const bcrypt = require('bcrypt');

const bcryptSalt = 10;

const passport = require('passport');

const ensureLogin = require('connect-ensure-login');
const user = require('../models/user');

function checkRoles(role) {
  return function(req, res, next) {
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    } 
    res.redirect('/login')
    
  };
}

const checkBoss = checkRoles('BOSS')

passportRouter.get('/edit', checkBoss, (req, res) => {
  res.render('passport/edit-employees', { user: req.user });
});

passportRouter.get('/signup', (req, res, next) => {
  res.render('passport/signup');
});

passportRouter.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const role = req.body.role;

  if (username === '' || password === '') {
    res.render('passport/signup', { message: 'Indicate username and password' });
    return;
  }

  user.findOne({ username })
    .then((user) => {
      if (user !== null) {
        res.render('passport/signup', { message: 'The username already exists' });
        return;
      }

      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new user({
        username,
        password: hashPass,
        role
      });

      newUser.save((err) => {
        if (err) {
          res.render('passport/signup', { message: 'Something went wrong' });
        } else {
          res.redirect('/');
        }
      });
    })
    .catch((error) => {
      next(error);
    });
});

passportRouter.get('/login', (req, res, next) => {
  res.render('passport/login');
});

passportRouter.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/passport/login',
  failureFlash: true,
  passReqToCallback: true
}));


passportRouter.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('passport/private', { user: req.user });
});

module.exports = passportRouter;
