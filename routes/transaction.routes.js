const express = require("express");
const router = express.Router();
const { verifyToken } = require("../middleware/authJwt");
const transactionController = require("../controllers/transaction.controller");

router.get("/", verifyToken, transactionController.getAllTransactions);

module.exports = router;
