//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));

// Ititialize Middleware

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: true,
  cookie: {}
}));
// This is the basic express session({..}) initialization.

app.use(passport.initialize());
// init passport on every route call.

app.use(passport.session());
// allow passport to use "express-session".

// connect to db "userDB"
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

mongoose.connection.on("error", err => {
    console.log("err", err)
});

mongoose.connection.on("connected", (err, res) => {
    console.log("mongoose is connected")
});

// schema of the model
// const userSchema = new mongoose.Schema({
//     email: { type: String, required: [true, 'Enter The email !'], },
//     password: { type: String, required: [true, 'Enter The password !'], },
// });

//Create a New User Schema for the database.
// This is required when using Mongoose
const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Create a New User Model based on a Schema.
const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// // use static serialize and deserialize of model for passport session support
// passport.serializeUser(function(user, done){
//   done(null, user);
// });
//
// passport.deserializeUser(function(user, done){
//   done(null, user);
// });

// Set up Google Strategy.
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id, username: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id, username: profile.displayName }, function(err, user) {
      return cb(err, user);
    });
  }
));

// GET
app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {
    scope:["email", "profile"]}
));

// BETTER WAY:
// app.route('/auth/google')
//   .get(passport.authenticate('google', {
//     scope: ['profile']
// }));

app.get("/auth/facebook", passport.authenticate("facebook", {
   scope: "public_profile" }
));


app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {userWithSecrets: foundUsers});
      }
    }
  });
});

app.route("/submit")
.get(function (req,res){
  if(req.isAuthenticated()){
    User.findById(req.user.id,function (err,foundUser){
      if(!err){
        res.render("submit",{secrets:foundUser.secret});
      }
    })
  }else {
    res.redirect("/login");
  }
})
.post(function (req, res){
  if(req.isAuthenticated()){
    User.findById(req.user.id,function (err, user){
      user.secret.push(req.body.secret);
      user.save(function (){
        res.redirect("/secrets");
      });
    });

  }else {
   res.redirect("/login");
  }
});

// OLD VERSION.
// app.get("/submit", function(req, res){
//   if(req.isAuthenticated()){
//     res.render("submit");
//   } else {
//     res.redirect("/login");
//   }
// });
//
// app.post("/submit", function(req, res){
//   console.log(req.user.id);
//
//   if(req.isAuthenticated()){
//     User.findById(req.user.id, function(err, user){
//       user.secret.push(req.body.secret);
//       user.save(function(){
//         res.redirect("/secrets");
//       });
//     });
//
//   } else {
//     res.redirect("/login");
//   }
// });

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

// POST
app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log("Error in registering" + err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        console.log(user, 101);
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
         res.redirect("/secrets");
     });
    }
  });
});

// The handling of the new route "/submit/delete"
app.post("/submit/delete",function (req, res){
  if(req.isAuthenticated()){
    User.findById(req.user.id, function (err,foundUser){
      foundUser.secret.splice(foundUser.secret.indexOf(req.body.secret),1);
      foundUser.save(function (err) {
        if(!err){
          res.redirect("/submit");
        }
      });
    });
  }else {
    res.redirect("/login");
  }
});

app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
