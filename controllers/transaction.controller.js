const db = require("../models");
const Transaction = db.transaction;

exports.getAllTransactions = async (req, res) => {
  try {
    const transactions = await Transaction.findAll({
      where: { userId: req.userId },
    });
    res.status(200).send(transactions);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};
