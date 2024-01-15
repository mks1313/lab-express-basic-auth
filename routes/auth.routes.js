const { Router } = require('express');
const router = new Router();
const User = require('../models/User.model');
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const authMiddleware = require('../middlewares/authMiddleware'); 

// SIGNUP ROUTES
router.get('/signup', (req, res) => res.render('auth/signup'));

router.post('/signup', authMiddleware, (req, res) => {
   const { username, password } = req.body;

   if (!username || !password) {
      return User.create({})
         .then(() => res.render('auth/signup', { errorMessage: 'Username and password are required.' }))
         .catch(error => res.render('auth/signup', { errorMessage: error.errors }));
   }

   bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(password, salt))
      .then(passwordHash => {
         return User.create({
            username,
            passwordHash,
         });
      })
      .then(newUser => {
         res.redirect('/userProfile');
      })
      .catch(error => {
         if (error.code === 11000) {
            res.render('auth/signup', { errorMessage: 'Username already exists.' });
         } else {
            res.render('auth/signup', { errorMessage: error.message });
         }
      });
});

// LOGIN ROUTES
router.get('/login', (req, res) => {
    if (req.session.currentUser) {
       res.redirect('/userProfile');
    } else {
       res.render('auth/login');
    }
 });

router.post('/login', authMiddleware, (req, res) => {
    const { username, password } = req.body;

    User.findOne({ username })
        .then(user => {
            if (!user) {
                res.render('auth/login', { errorMessage: 'User not found or incorrect password.' });
            } else {
                if (bcryptjs.compareSync(password, user.passwordHash)) {
                  const { passwordHash, ...userWithoutPassword } = user.toObject();
                  req.session.currentUser = userWithoutPassword;
                  res.redirect('/userProfile');
                } else {
                    res.render('auth/login', { errorMessage: 'User not found or incorrect password.' });
                }
            }
        })
        .catch(error => res.render('auth/login', { errorMessage: error.message }));
});

// USER PROFILE ROUTES
router.get('/userProfile', authMiddleware, (req, res) => {
    res.render('users/user-profile');
});

// LOGOUT ROUTE
router.post('/logout', (req, res) => {
   req.session.destroy((error) => {
      if (error) {
         console.error('Error destroying session:', error);
         return res.status(500).json({ errorMessage: 'Internal Server Error' });
      }
      
      res.redirect('/');
   });
});


// PROTECTED ROUTES
router.get('/main', authMiddleware, (req, res) => {
    res.render('main');
});

router.get('/private', authMiddleware, (req, res) => {
    res.render('private');
});

module.exports = router;

