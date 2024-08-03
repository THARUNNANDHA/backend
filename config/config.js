const { Sequelize } = require('sequelize');
var nodemailer = require('nodemailer');

// const sequelize = new Sequelize('practice_db', 'postgres', 'Ntharun123', {
//     host: 'localhost',
//     dialect: 'postgres',
//     logging: false
// });

const sequelize = new Sequelize("postgres://default:d5IcjRg9lMDY@ep-flat-river-a4udalva.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require", {
    dialect: 'postgres',
    protocol: 'postgres',
    logging: false,
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false
        }
    }
});

sequelize.authenticate()
    .then(() => {
        console.log('Connection has been established successfully.');
    })
    .catch(err => {
        console.error('Unable to connect to the database:', err);
    });


var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        // user: process.env.MAIL_USER,
        // pass: process.env.APP_PASS
        user: "ntharun832jacky@gmail.com",
        pass: "dogo ruiu ogty lrtp"
    }
});

module.exports = {
    sequelize,
    transporter
};
