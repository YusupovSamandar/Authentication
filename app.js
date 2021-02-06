require("dotenv").config();
const express = require("express"),
    bodyParser = require("body-parser"),
    ejs = require("ejs"),
    api = express(),
    mongoose = require("mongoose"),
    session = require("express-session"),
    passport = require("passport"),
    passportLocalMongoose = require("passport-local-mongoose"),
    GoogleStrategy = require('passport-google-oauth20').Strategy,
    FacebookStrategy = require("passport-facebook").Strategy,
    findOrCreate = require("mongoose-findorcreate");

api.use(express.static("public"));

api.set('view engine', 'ejs');

api.use(bodyParser.urlencoded({
    extended: true
}));

api.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

api.use(passport.initialize());
api.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String,
    facebookId: String
});

userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

api.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile']
    })
);

api.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        res.redirect('/secrets');
    }
);

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

api.get('/auth/facebook',
    passport.authenticate('facebook')
);

api.get('/auth/facebook/secrets',
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        res.redirect('/secrets');
    }
);

api.get("/", (req, res) => {
    res.render("home");
});

api.get("/login", (req, res) => {
    res.render("login");
});

api.get("/register", (req, res) => {
    res.render("register");

});

api.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}, (err, foundUsers) =>{
        if(err){
            console.log(err);
        }else{
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

api.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

api.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    
    User.findById(req.user._id, (err, foundUser) =>{
        if (err) {
            console.log(err);
        }else{
            if (foundUser) {
                foundUser.secret = submittedSecret
                foundUser.save(() => {
                    res.redirect("/secrets")
                });
            }
        }
    });
});

api.get("/logout", (req, res) => {
    req.logOut();
    res.redirect("/");
});

api.post("/register", (req, res, next) => {
    User.register({
        username: req.body.username
    }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

api.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("secrets")
            });
        }
    });
});

api.listen(3000, () => {
    console.log("Server started on port 3000");
});
