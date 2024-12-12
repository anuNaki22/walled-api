const db = require("../models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = db.user;

exports.register = async (req, res) => {
  try {
    const { fullName, email, password, phonenumber } = req.body;

    // Cek apakah email sudah terdaftar
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).send({ message: "Email already registered!" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 8);

    // Buat user baru
    const user = await User.create({
      fullName,
      email,
      password: hashedPassword,
      phonenumber,
      balance: 5000000, // Default balance
    });

    // Exclude password manually
    const userResponse = {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phonenumber: user.phonenumber,
      balance: user.balance,
    };

    res
      .status(201)
      .send({ message: "User registered successfully!", user: userResponse });
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

    // Convert user instance to plain object
    const userObject = user.get({ plain: true });
    // Remove the password field
    delete userObject.password;

    res.status(200).send({ user: userObject, accessToken: token });
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
