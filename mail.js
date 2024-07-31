require('dotenv').config();
var nodemailer = require('nodemailer');
var { transporter } = require('./config/config');

function sendmail(to_address, subject, text) {
    console.log("\n\n\n\n\n", to_address, subject, text);
    var mailOptions = {
        from: process.env.MAIL_USER,
        to: to_address,
        subject: subject,
        text: text
    };

    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}
module.exports = sendmail;