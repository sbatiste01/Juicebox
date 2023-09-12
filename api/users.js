require("dotenv").config()
const express = require('express');
const usersRouter = express.Router();
const bcrypt = require("bcrypt")

const {
  createUser,
  getAllUsers,
  getUserByUsername,
} = require('../db');

const jwt = require('jsonwebtoken');

usersRouter.get('/', async (req, res, next) => {
  try {
    const users = await getAllUsers();

    res.send({
      users
    });
  } catch ({ name, message }) {
    next({ name, message });
  }
});

usersRouter.post('/login', async (req, res, next) => {
  const { username, password } = req.body;

  // request must have both
  if (!username || !password) {
    next({
      name: "MissingCredentialsError",
      message: "Please supply both a username and password"
    });
  }

  try {
    const user = await getUserByUsername(username);

    // Check to see if password matches
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      const token = jwt.sign({
        id: user.id,
        username
      }, process.env.JWT_SECRET, {
        expiresIn: '1w'
      });

      res.send({
        message: "you're logged in!",
        token
      });
    } else {
      next({
        name: 'IncorrectCredentialsError',
        message: 'Username or password is incorrect'
      });
    }

  } catch (error) {
    console.log(error);
    next(error);
  }
});

usersRouter.post('/register', async (req, res, next) => {
  const { username, password, name, location } = req.body;

  // Encrypt password before storing in database
  const passwdEncrypted = await bcrypt.hash(password, 10)

  try {
    const _user = await getUserByUsername(username);

    if (_user) {
      next({
        name: 'UserExistsError',
        message: 'A user by that username already exists'
      });
    }

    const user = await createUser({
      username,
      password: passwdEncrypted,  // This is the encrypted password
      name,
      location,
    });

    // Token is created and payload is assigned id & username
    const token = jwt.sign({
      id: user.id,
      username
    }, process.env.JWT_SECRET, {
      expiresIn: '1w'
    });

    res.send({
      message: "thank you for signing up",
      token
    });
  } catch ({ name, message }) {
    next({ name, message });
  }
});

module.exports = usersRouter;