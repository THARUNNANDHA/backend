const { DataTypes } = require('sequelize');

const { sequelize } = require('../config/config');

const User123 = sequelize.define('user456', {
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    otp: {
        type: DataTypes.INTEGER,
        allowNull: true
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: "user"
    }

})

module.exports = User123;