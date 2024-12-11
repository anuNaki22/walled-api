const db = require("../models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = db.user;

exports.register = async (req, res) => {
  try {
    const { fullName, email, password, phonenumber } = req.body;
    const hashedPassword = await bcrypt.hash(password, 8);

    const user = await User.create({
      fullName,
      email,
      password: hashedPassword,
      phonenumber,
      balance: 5000000, // default balance
    });

    res.status(201).send({ message: "User registered successfully!", user });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user) return res.status(404).send({ message: "User not found!" });

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid)
      return res.status(401).send({ message: "Invalid Password!" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: 86400, // 24 hours
    });

    res.status(200).send({ user, accessToken: token });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.me = async (req, res) => {
  try {
    const user = await User.findByPk(req.userId); // Mengambil data user berdasarkan userId dari token

    if (!user) {
      return res.status(404).send({ message: "User not found!" });
    }

    res.status(200).send({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phonenumber: user.phonenumber,
      balance: user.balance,
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};