const LocalStrategy = require("passport-local").Strategy;
const passport = require('passport');
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const Joi = require('joi');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
////////////////////////////////////////////////////////////////////////////////////////////
passport.use(
	new LocalStrategy({ 
		usernameField: "email", 
		passwordField: "password" , 
	}, (email, password, done) => {
		pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
			if (err) {
				throw err;
			}
			if (result.rows.length > 0) {
				const user = result.rows[0];
				bcrypt.compare(password, user.password, (err, isMatch) => {
					if (err) { 
						console.log(err);
					}
					if (isMatch) {
						return done(null, user);
					} else {
						return done(null, false, { message: "Incorrect email address or password" });
					}
				});
			} else {
				return done(null, false, { 
					message: "Incorrect email address or password" 
				}); 
			}
			});
}));
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
	pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
		if (err) {
			return done(err);
		}
		console.log(`ID is ${results.rows[0].id}`);
		return done(null, results.rows[0]);
	});
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function initialize(passport) {
	console.log("Initialized");
}
module.exports = initialize;
