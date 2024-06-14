require('dotenv').config(); // Load environment variables from .env file

const ConnectToMongodb = require('./db');
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();
const passport = require('passport'); // Import Passport
require('./passport-config'); // Import your Passport configuration
const jwtMiddleware = require('./jwtmiddleware');
const path=require('path')
var cors = require('cors');
const dbHost = process.env.DB_HOST;



ConnectToMongodb();
const port = process.env.PORT;

app.use(cors());
app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(bodyParser.json());

app.use(passport.initialize());
app.use('/uploads/profile-pictures', express.static(path.join(__dirname, 'uploads', 'profile-pictures')));
app.use('/uploads/LeadPicture', express.static(path.join(__dirname, 'uploads', 'LeadPicture')));
app.use('/uploads/pictures', express.static(path.join(__dirname, 'uploads', 'pictures')));
app.use('/uploads/audio', express.static(path.join(__dirname, 'uploads', 'audio')));
app.use(express.static('uploads')); // 'uploads' should be the directory where your images are stored

// Endpoint to register for free trial
app.post('/register', (req, res) => {
  const { name } = req.body;
  const registrationDate = new Date();
  const registrationEndDate = new Date(registrationDate.getTime() + 5 * 24 * 60 * 60 * 1000); // 5 days from now

  // Save registration data to file
  const newData = {
    name,
    registrationDate,
    registrationEndDate,
    status: 'registered'
  };

  fs.writeFileSync('registration.json', JSON.stringify(newData));

  res.json({ message: 'Registration successful', data: newData });
});

// Endpoint to register for yearly subscription
app.post('/subscribe-yearly', (req, res) => {
  const { name } = req.body;
  const subscriptionStartDate = new Date();
  const subscriptionEndDate = new Date(subscriptionStartDate.getTime() + 365 * 24 * 60 * 60 * 1000); // 365 days from now

  // Save subscription data to file
  const newData = {
    name,
    subscriptionStartDate,
    subscriptionEndDate,
    status: 'subscribed'
  };

  fs.writeFileSync('subscription.json', JSON.stringify(newData));

  res.json({ message: 'Yearly subscription successful', data: newData });
});

// API endpoint to get subscription details
app.get('/api/subscription', (req, res) => {
  const filePath = path.join(__dirname, 'subscription.json');
  fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
          return res.status(500).json({ error: 'Failed to read subscription file' });
      }
      try {
          const subscription = JSON.parse(data);
          res.json(subscription);
      } catch (parseErr) {
          res.status(500).json({ error: 'Failed to parse subscription file' });
      }
  });
});

// API endpoint to get registration details
app.get('/api/registration', (req, res) => {
  const filePath = path.join(__dirname, 'registration.json');
  fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
          return res.status(500).json({ error: 'Failed to read registration file' });
      }
      try {
          const registration = JSON.parse(data);
          res.json(registration);
      } catch (parseErr) {
          res.status(500).json({ error: 'Failed to parse registration file' });
      }
  });
});




app.use('/api/auth', require('./routes/auth'));
app.use('/api/company', require('./routes/company'));
app.use('/api/employee', require('./routes/employee'));
app.use('/api/subemployee', require('./routes/subemployee'));
app.use('/api/task', require('./routes/task'));
app.use('/api/notification', require('./routes/notification'));
app.use('/api/lead', require('./routes/lead'));
app.use('/api/files', require('./routes/fileRoutes')); // Adjust the path as needed
app.use('/api/employee', jwtMiddleware); // Apply middleware to employee-related routes


app.listen(port, () => {
  console.log(`Task-Manager backend listening at http://${dbHost}:${port}`);
});

// const mysql = require('mysql');
// const express = require('express');

// const app = express();
// const port = 5000;

// // MySQL connection configuration
// // const connection = mysql.createConnection({
// //     host: 'localhost',
// //     user: 'u480626506_sonam',
// //     password: 'Z1*dFA3x',
// //     database: 'u480626506_sonam'
// // });
// const connection = mysql.createConnection({
//   host: 'localhost',
//   user: 'KD3_70202',
//   password: 'manager',
//   database: 'ab'
// });

// // Connect to MySQL
// connection.connect((err) => {
//     if (err) {
//         console.error('Error connecting to the database:', err.stack);
//         return;
//     }
//     console.log('Connected to the database as id ' + connection.threadId);
// });

// // Basic route
// app.get('/', (req, res) => {
//     res.send('Hello World!');
// });

// app.get('/',(req,res)=>{

//   res.send('hiii');
// })
// // Route to test database connection
// app.get('/test-db', (req, res) => {
//     connection.query('SELECT 1 + 1 AS solution', (err, results, fields) => {
//         if (err) {
//             res.status(500).send('Error querying the database');
//             return;
//         }
//         res.send('The solution is: ' + results[0].solution);
//     });
// });

// // Start the server
// app.listen(port, () => {
//     console.log(`Server is running on http://localhost:${port}`);
// });



// const express = require('express');
// const app = express();
// const port = 5000;
// //const userRoutes = require('./routes');

// // Middleware to parse JSON bodies
// app.use(express.json());

// // Use the user routes
// //app.use('/api', userRoutes);
// app.use('/api/mysql', require('./routes/mysql'));

// // Basic route
// app.get('/', (req, res) => {
//     res.send('Hello World!');
// });

// // Start the server
// app.listen(port, () => {
//     console.log(`Server is running on http://localhost:${port}`);
// });
