const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const randomstring = require('randomstring');
const bodyParser = require("body-parser");
const pg = require('pg');
require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 4000;
const initializePassport = require("./passportConfig");
initializePassport(passport);
///////////////////////////////////////////////////////////////////////////////////////////////////////
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
///////////////////////////////////////////////////////////////////////////////////////////////////////
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: false
	})
);
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/", (req, res) => {
	res.render('index');
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
app.post('/users/logout', function(req, res, next) {
	req.logout(function(err) {
		if (err) { return next(err); }
		req.flash("logout_msg", "You have successfully logged out!");
		res.render("index.ejs");
	});
});
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
	console.log('req.isAuthenticated:', req.isAuthenticated(), 'req.session.flash:', req.session.flash);
	res.render("dashboard.ejs", {user: req.user.name});
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
//app.get('/users/dashboard', (req, res) => {
//	const query = 'SELECT * FROM posts';
//	pool.query(query, (err, res) => {
//		if (err) throw err;
//		console.log(res.rows);
//		res.render("index", { forms: res.rows });
//		req.flash('success', `Post Details: ${post.title}, ${post.description}, ${post.name}`);
//		res.render('index.ejs', { post });
//});
//});  
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
