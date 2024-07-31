const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/config')

const Googleuserdata = sequelize.define('Googleuser', {
    picture: {
        type: DataTypes.STRING,
        allowNull: false
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false
    },
    sub: {
        type: DataTypes.STRING,
        allowNull: false
    },
    otp: {
        type: DataTypes.INTEGER,
        allowNull: true
    }
})

module.exports = Googleuserdata;