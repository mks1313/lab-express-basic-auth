module.exports = (req, res, next) => {
    if (req.path === '/login' || req.path === '/signup') {
      return next();
    }
    if (req.session.currentUser) {
      next();
    } else {
      res.redirect('/login');
    }
  };
  