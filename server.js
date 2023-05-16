const express = require("express");
const sgMail = require('@sendgrid/mail');
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const bodyParser = require("body-parser");
const cookieParser = require('cookieparser');
const crypto = require('crypto');
const pg = require('pg');
const passwordValidator = require('password-validator');
require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 4000;
const initializePassport = require("./passportConfig");
initializePassport(passport);
const API_KEY = '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';
sgMail.setApiKey(API_KEY);
///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: false
	})
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/", (req, res) => {
	res.redirect("/users/index");
});
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/users/register", checkAuthenticated, (req, res) => {
	res.render("register.ejs");
});
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/users/login", checkAuthenticated, (req, res) => {
	console.log(req.session.flash.error);
	res.render("login.ejs");
});
/////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/users/logout', function(req, res, next) {
	req.logout(function(err) {
		if (err) { return next(err); }
		res.redirect("/users/index");
	});
});
////////////////////////////////////////////////////////////////////////////////////////////////////////
const passwordSchema = new passwordValidator();
passwordSchema
.is().min(12)
.is().max(50)
.has().uppercase()
.has().lowercase()
.has().digits()
.has().symbols();
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/users/register", async (req, res) => {
	let { name, email, password, password2 } = req.body;
	let errors = [];
	console.log({name,email,password,password2});
	if (!name || !email || !password || !password2) {
		errors.push({ message: "Please enter all fields" });
	}
	if (password.length < 11) {
		errors.push({ message: "Password must be a least 12 characters long" });
	}
	if (password !== password2) {
		errors.push({ message: "Passwords do not match" });
	}
	if (!passwordSchema.validate(password)) {
		errors.push({ message: "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit and a special character" });
	}
	if (errors.length > 0) {
		res.render("register", { errors, name, email, password, password2 });
	} else {
		hashedPassword = await bcrypt.hash(password, 10);
		console.log(hashedPassword);
		pool.query(`SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
			if (err) {
				console.log(err);
			}
			console.log(results.rows);
			if (results.rows.length > 0) {
				req.flash("already_msg", "This email already exists. Please login instead");
				res.redirect("/users/register");
			} else {
				pool.query(`INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, password`, [name, email, hashedPassword], (err, results) => {
					if (err) {
						throw err;
					}
					console.log(results.rows);
					req.flash("success_msg", "You are now registered. Please log in");
					res.redirect("/users/login");
				});
			}
		});
	}
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/users/login", 
	passport.authenticate("local", { 
		successRedirect: "/users/2fa", 
		failureRedirect: "/users/login", 
		failureFlash: true 
	})
);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/users/dashboard", (req, res) => {
	const { title, description } = req.body;
	const personName = req.user.name;
	pool.query('INSERT INTO posts (title, description, name) VALUES ($1, $2, $3)',
		[title, description, personName], (err, result) => {
	if (err) { 
		throw err;
	} else {
		req.flash("success_msg","Posted Successfully!");
		res.redirect("/users/dashboard");
	}
	});
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/users/index', (req, res) => {
	const query = 'SELECT title, description, name, to_char(date, \'DD-Mon-YYYY\') AS short_date, to_char(time, \'HH:MM\') AS short_time FROM posts';
	pool.query(query, (err, response) => {
		console.log(response.rows);
		res.render("index.ejs", {form: response.rows}); 
	});
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
	pool.query('SELECT title, description, to_char(date, \'DD-Mon-YYYY\') AS short_date, to_char(time, \'HH:MM\') AS short_time FROM posts WHERE name = $1', [req.user.name], (err, result) => {
		console.log(result.rows);
		res.render('dashboard', {form: result.rows, user: req.user.name});
	});
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/search', async (req, res) => {
	const { query } = req.query; 
	const result = await pool.query('SELECT * FROM posts WHERE name ILIKE $1', [`%${query}%`]);
	console.log(result.rows);
	res.json(result.rows);
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/users/2fa', checkNotAuthenticated, async (req, res) => {
	const email = req.user.email;
	const userId = req.user.id;
	const token = crypto.randomBytes(64).toString('hex');
	await pool.query(
		'UPDATE users SET verification_token = $1, verified = $2 WHERE id = $3', [token, false, userId]
	);
	const verificationLink = `http://${req.headers.host}/users/verify?token=${token}`;
	const msg = {
		from: {
			name: 'UEA Blog',
			email: 'a.pareek@uea.ac.uk'
		},
		to: email,
		subject: 'Verification Link',
		html: `Click the following link to verify your email: <a href="${verificationLink}">${verificationLink}</a>`
	};
	await sgMail.send(msg);
	res.render('login.ejs', { successmsg: "Check your email for login URL" });
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get('/users/verify', async (req, res) => {
	const { token } = req.query;
	try {
		const query = 'SELECT * FROM users WHERE verification_token = $1';
		const result = await pool.query(query, [token]);
		if (result.rowCount === 0) {
			res.status(400).json({ message: 'Invalid token. Please try again.' });
		} else {
			const updateQuery = 'UPDATE users SET verified = true WHERE verification_token = $1';
			await pool.query(updateQuery, [token]);
			res.render("dashboard");
//			res.status(200).json({ message: 'Verification successful. Please log in.' });
		}
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Verification failed. Please try again later.' });
	}
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function checkAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return res.redirect("/users/dashboard");
	}
	next();
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function checkNotAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	}
	res.redirect("/users/login");
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
