const DataTypes = require('sequelize')
const { sequelize } = require('../config/config')

const Cart = sequelize.define('cart', {
    userid: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    map: {
        type: DataTypes.JSON,
        allowNull: false
    }
})
module.exports = Cart;