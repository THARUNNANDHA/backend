const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/config')


const Product = sequelize.define('Product', {
    image_src: {
        type: DataTypes.STRING
    },
    description: {
        type: DataTypes.STRING
    },
    price: {
        type: DataTypes.INTEGER
    },
    title: {
        type: DataTypes.STRING
    }
})
module.exports = Product;