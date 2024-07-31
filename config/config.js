const { Sequelize } = require('sequelize');
var nodemailer = require('nodemailer');

const sequelize = new Sequelize('practice_db', 'postgres', 'Ntharun123', {
    host: 'localhost',
    dialect: 'postgres',
    logging: false
});

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.APP_PASS
    }
});

module.exports = {
    sequelize,
    transporter
};
