var express = require('express');
var app     = express();

var passport      = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mongoose=require('mongoose');
var bodyParser = require('body-parser');
var multer     = require('multer'); 
var dbUri='mongodb://localhost/passportJsApp';
var db=mongoose.connect(dbUri);
var cookieParser = require('cookie-parser');
var session      = require('express-session');
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

app.use(cookieParser())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'this is the secret' }));
app.use(multer());
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(__dirname + '/public'));

var userSchema= new mongoose.Schema({
    username: String,
    password: String,
    firstName: String,
    lastName: String,
    email: String,
    roles:[String],
    google:{
        id : String,
        token: String
    }
});

var userModel= mongoose.model("userModel",userSchema);

/*var aakash=new userModel({
    username: 'aakash',
    password: 'aakash',
    firstName: 'aakash',
    lastName: 'chandhoke',
    email: 'aakash.chandhoke24@gmail.com',
    roles:['admin','faculty']
});

aakash.save();*/

userModel.createUser=createUser;


function createUser(user){
 return userModel.create(user);
}
passport.use(new LocalStrategy(
function(username, password, done)
{
        userModel.findOne({username:username,password:password},function(err,user){ //assynchronus call 
            if(user)
            {
                return done(null,user);                 
            }
            return done(null,false);
        });
        
}));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

var auth = function(req, res, next)
{
    if (!req.isAuthenticated())
        res.send(401);
    else
        next();
};

var googleConfig = {
    /*clientID     : process.env.GOOGLE_CLIENT_ID,
    clientSecret : process.env.GOOGLE_CLIENT_SECRET,
    callbackURL  : process.env.GOOGLE_CALLBACK_URL*/
    clientID     : '875491190225-2es1ou67nkv090u1bcphna00h79puinf.apps.googleusercontent.com',
    clientSecret : 'kXKuMsBqZslp6oQLdDqFX6WZ',
    callbackURL  : 'http://127.0.0.1:3000/auth/google/callback'
};

passport.use(new GoogleStrategy(googleConfig, googleStrategy));

function googleStrategy(token, refreshToken, profile, done) {
    userModel
        .findUserByGoogleId(profile.id)
        .then(
            function(user) {
                if(user) {
                    return done(null, user);
                } else {
                    var email = profile.emails[0].value;
                    var emailParts = email.split("@");
                    var newGoogleUser = {
                        username:  emailParts[0],
                        firstName: profile.name.givenName,
                        lastName:  profile.name.familyName,
                        email:     email,
                        google: {
                            id:    profile.id,
                            token: token
                        }
                    };
                    return userModel.createUser(newGoogleUser);
                }
            },
            function(err) {
                if (err) { return done(err); }
            }
        )
        .then(
            function(user){
                return done(null, user);
            },
            function(err){
                if (err) { return done(err); }
            }
        );
}
userModel.findUserByGoogleId=findUserByGoogleId;

function findUserByGoogleId(googleId){
    return userModel.findOne({'google.id':googleId});
}

app.get('/loggedin', function(req, res)
{
    res.send(req.isAuthenticated() ? req.user : '0');
});
    
app.post('/login', passport.authenticate('local'), function(req, res)
{
    res.send(req.user);
});

app.post('/logout', function(req, res)
{
    req.logout();
    res.send(200);
});  

app.get('/auth/google',passport.authenticate('google', { scope : ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', {
        successRedirect: '/#/profile',
        failureRedirect: '/#/login'
    }));

app.post('/register',function(req,res){
    var newUser=new userModel(req.body);
    newUser.roles=['student'];
    newUser.save(function(err,user){
        req.login(user,function(err,user){
            if(err){
                return next(err);
            }
            res.json(user);
        });
    });
}); 

app.listen(3000);
