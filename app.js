require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const findOrCreate = require('mongoose-findorcreate');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const FacebookStrategy = require('passport-facebook').Strategy;

const app = require("https-localhost")()
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true}));

app.use(session({
  secret: "Little Secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/authDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  facebookId: String,
  secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos', 'email']
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      console.log(profile);
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render('home');
});

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    window.location.pathname = "/secrets";
    // res.redirect('/secrets');
});

app.get("/register", (req, res) => {
  res.render('register');
});

app.get("/login", (req, res) => {
  res.render('login');
});

app.get("/secrets", (req, res) => {
  if(req.isAuthenticated()){
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
      if(err){
        console.log(err);
      }else {
        res.render('secrets', {usersSecrets: foundUsers});
      }
    });
  }else {
    res.redirect("/login")
  }
});

app.get("/submit", (req, res) => {
  if(req.isAuthenticated()){
    res.render('submit');
  }else {
    res.redirect("/login");
  }
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else {
      foundUser.secret = submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/login");
});

app.post("/register", (req, res) => {
  console.log(req.body);
  User.register({ username: req.body.username }, req.body.password, function(err, user) {
    if(err){
      console.log(err);
      res.redirect("/register")
    }else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
})

app.listen(3000, () => {
  console.log("Server start running successfully");
});

