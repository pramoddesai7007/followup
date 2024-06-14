require('dotenv').config(); // Load environment variables from .env file


// First step is to connect with our database
const mongoose = require('mongoose')
mongoURI = process.env.MONGO_URI


const ConnectToMongodb = (() => {
    mongoose.connect(mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
        .then(() => {
            console.log("Connected to Mongo Successfully")
        }).catch((e) => {
            console.log(e)
        })
})

module.exports = ConnectToMongodb
// const mysql = require('mysql');

// const connection = mysql.createConnection({
//     host: 'localhost',
//     user: 'KD3_70202',
//     password: 'manager',
//     database: 'ab'
// });

// connection.connect((err) => {
//     if (err) {
//         console.error('Error connecting to the database:', err.stack);
//         return;
//     }
//     console.log('Connected to the database as id ' + connection.threadId);
// });

// module.exports = connection;
