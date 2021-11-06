const router = require('express').Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require('../secrets'); // use this secret!
const jwt = require('jsonwebtoken');
const { add, findBy } = require('../users/users-model');
const bcrypt = require('bcryptjs');

router.post('/register', validateRoleName, (req, res, next) => {
  let user = req.body;

  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds);

  user.password = hash;

  add(user)
    .then((savedUser) => {
      res.status(201).json({ savedUser });
    })
    .catch(next);
});

router.post('/login', checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = makeToken(user);
        res.status(200).json({
          message: `${username} is back!`,
          token,
        });
      } else {
        next({ status: 401, message: 'Invalid Credentials' });
      }
    })
    .catch(next);
});

const makeToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.usernmae,
    role_name: user.role_name,
  };

  const options = {
    expiresIn: '60s',
  };

  return jwt.sign(payload, JWT_SECRET, options);
};

module.exports = router;
