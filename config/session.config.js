const session = require('express-session');
const MongoStore = require('connect-mongo');


module.exports = app => {
  app.set('trust proxy', 1);

  

  app.use(
    session({
      secret: process.env.SESS_SECRET || '123mahadaonda321',
      resave: true,
      saveUninitialized: false,
      cookie: {
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 60000 
      },
      store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/lab-express-basic-auth',
        ttl: 60 * 60 * 24 
      })
    })
  );
};
