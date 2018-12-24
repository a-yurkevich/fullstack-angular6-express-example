const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // в переменной User та модель которая позволяет работать с БД
const keys = require('../config/keys');
const errorHandler = require('../utils/errorHandler');

module.exports.login = async function (req, res) {
  const condidate = await User.findOne({email: req.body.email});

  if (condidate) {
    const passwordResult = bcrypt.compareSync(req.body.password, condidate.password);

    if (passwordResult) {
      // Генерация токена, пароли совпали
      const token = jwt.sign({
        email: condidate.email,
        userId: condidate._id
      }, keys.jwt, {expiresIn: 60 * 60});

      res.status(200).json({
        token: `Bearer ${token}`
      });

    } else {
      // Пароли не совпали
      res.status(401).json({
        message: 'Пароли не совпадают. Попробуйте снова.'
      });
    }

  } else {
    res.status(404).json({
      message: 'Пользователь с таким email не найден.'
    });
  }
};

module.exports.register = async function (req, res) {
  const condidate = await User.findOne({email: req.body.email});

  if (condidate) {
    res.status(409).json({
      message: 'Такой email уже занят. Попробуйте другой.'
    });
  } else {
    const salt = bcrypt.genSaltSync(10),
      password = req.body.password;
    const user = new User({
      email: req.body.email,
      password: bcrypt.hashSync(password, salt)
    });

    try {
      await user.save();
      res.status(201).json(user);
    } catch (e) {
      errorHandler(res, e);
    }

  }
};
