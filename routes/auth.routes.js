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
      .then(userFromDB => {
        console.log('Newly created user is: ', userFromDB);
        res.redirect('/user-profile');
      })
      .catch(error => next(error));
});

module.exports = router;