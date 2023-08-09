const { Router } = require('express');
const router = new Router();
const User = require('../models/User.model');

//encrypt requirements
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

router.get("/sign-up", (req, res, next) => {
    res.render("auth/sign-up");
});

router.get('/user-profile', (req, res) => res.render('users/users-profile'));

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
        res.render('users/users-profile', {user});
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
        res.render('users/users-profile', { user });
      } else {
        console.log("Incorrect password. ");
        res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
      }
    })
    .catch(error => next(error));
});

module.exports = router;