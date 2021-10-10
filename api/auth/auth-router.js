const bcrypt = require('bcryptjs');
const router = require('express').Router();
const { JWT_SECRET } = require("../config/secrets");
const jwt = require('jsonwebtoken');
const { checkUsernameDoesNotExists, checkNewUserPayload, checkUsernameExists } = require('./auth-middleware');
const { add } = require('./auth-model');

router.post('/register', checkUsernameDoesNotExists, checkNewUserPayload, (req, res, next) => {
  const { username, password } = req.body;

  const hash = bcrypt.hashSync(password, 8);
  add({ username, password: hash })
    .then(data => {
      res.status(201).json(data);
    })
    .catch(next);
});

router.post('/login', checkUsernameExists,(req, res, next) => {
  const createToken = (user) => {
    const payload = {
      subject: user.id,
      username: user.username,
    };

    const options = {
      expiresIn: '1d',
    };

    return jwt.sign(payload, JWT_SECRET, options);
  };

  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = createToken(req.user);
    res.json({
      message: `Welcome, ${req.user.username}`,
      token,
    });
  } else {
    next({
      status: 401,
      message: "Invalid credentials",
    });
  }
});

module.exports = router;
