const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const randomstring = require('randomstring');
const bodyParser = require("body-parser");
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const cookieParser = require('cookieparser');
const pg = require('pg');
require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 4000;
const initializePassport = require("./passportConfig");
initializePassport(passport);
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
		successRedirect: "/users/dashboard", 
		failureRedirect: "/users/login", 
		failureFlash: true 
	})
);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/users/dashboard", (req, res) => {
	const { title, description } = req.body;
	const personName = req.user.name;
	const token = req.csrfToken();
	if (req.body._csrf !== token) {
		return res.status(403).send('CSRF token invalid');
	}
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
