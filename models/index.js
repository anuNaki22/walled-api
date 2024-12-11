const { Sequelize, DataTypes } = require("sequelize");
const config = require("../config/config");

const sequelize = new Sequelize(config.development);

const db = {};
db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.user = require("./user.model")(sequelize, DataTypes);
db.transaction = require("./transaction.model")(sequelize, DataTypes);

db.user.hasMany(db.transaction, { as: "transactions" });
db.transaction.belongsTo(db.user, {
  foreignKey: "userId",
  as: "user",
});

module.exports = db;
