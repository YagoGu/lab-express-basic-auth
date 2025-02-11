const { Router } = require('express');
const router = new Router();
const User = require('../models/User.model');

//encrypt requirements
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

// routes/auth.routes.js

// ... all other imports stay unchanged

// require auth middleware
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

// ...
router.get("/sign-up", (req, res, next) => {
    res.render("auth/sign-up");
});
// nothing gets changed except the GET /userProfile route
//
//                         .: ADDED :.
router.get('/user-profile', isLoggedIn, (req, res) => {
  res.render('users/users-profile', { userInSession: req.session.currentUser })
});

router.get('/main', isLoggedIn, (req, res) => {
  res.render('users/main', { userInSession: req.session.currentUser })
});

router.get('/private', isLoggedIn, (req, res) => {
  res.render('users/private', { userInSession: req.session.currentUser })
});

router.post("/sign-up", (req, res, next) => {
    // console.log(req.body);
    const { username, hashedPassword } = req.body;

    if (!username || !hashedPassword) {
      res.render('auth/sign-up', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
      return;
    }
 
    bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(hashedPassword, salt))
      .then(hashedPassword => {
        // console.log(`Password hash: ${hashedPassword}`);
        return User.create({
            username,
            hashedPassword,
        })
      })
      .then(user => {
        console.log(user.username)
        // console.log('Newly created user is: ', userFromDB);
        // res.render('users/users-profile', {user});
        req.session.currentUser = user;
        res.redirect('/user-profile');
      })
      .catch(error => {
        if (error.code === 11000) {
          console.log(" Username and email need to be unique. Either username or email is already used. ");
          res.status(500).render('auth/signup', {
             errorMessage: 'User not found and/or incorrect password.'
          });
        } 
        else {
          next(error);
        }
      });
});

router.get('/login', (req, res) => res.render('auth/login'));

router.post('/login', (req, res, next) => {
  const { username, hashedPassword } = req.body;
 
  console.log('SESSION =====> ', req.session);
  // everything else stays untouched
  if (username === '' || hashedPassword === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, email and password to login.'
    });
    return;
  }
  
  User.findOne({ username })
    .then(user => {
      if (!user) {
        console.log("Username not registered. ");
        res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
        return;
      } else if (bcryptjs.compareSync(hashedPassword, user.hashedPassword)) {
        // res.render('users/users-profile', { user });
        req.session.currentUser = user;
        res.redirect('/user-profile');
      } else {
        console.log("Incorrect password. ");
        res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
      }
    })
    .catch(error => next(error));
});

router.post('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});

module.exports = router;