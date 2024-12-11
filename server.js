require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./models");

const app = express();
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", require("./routes/auth.routes"));
app.use("/api/transactions", require("./routes/transaction.routes"));

// Sync DB
db.sequelize
  .sync()
  .then(() => console.log("Database synced"))
  .catch((err) => console.log("Failed to sync db:", err.message));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
