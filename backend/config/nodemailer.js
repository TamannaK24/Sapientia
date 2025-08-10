import nodemailer from 'nodemailer'

const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    }
});

transporter.verify((err, success) => {
    if (err) {
        console.error("SMTP connection failed", err.message);
    } else {
        console.log("Email server ready to send messages"); 
    }
});

export default transporter; 