
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const DB_FILE = path.join(__dirname, 'strike.db');

const DB = new sqlite3.Database(DB_FILE);
DB.serialize(() => {
  DB.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    passwordHash TEXT,
    accountJson TEXT,
    createdAt INTEGER,
    updatedAt INTEGER
  )`);
  DB.run(`CREATE TABLE IF NOT EXISTS resets (
    token TEXT PRIMARY KEY,
    userId INTEGER,
    expiresAt INTEGER
  )`);
});

const app = express();
app.use(cors());
app.use(express.json({limit:'200kb'}));

const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_in_production';
const PORT = process.env.PORT || 3000;

function createToken(payload){ return jwt.sign(payload, JWT_SECRET, {expiresIn:'30d'}); }

function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:'no token'});
  const token = h.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err,user)=>{
    if(err) return res.status(401).json({error:'invalid token'});
    req.user = user; next();
  });
}

function safeParseAccount(j){ try{ return JSON.parse(j||'{}'); }catch(e){ return {}; }}

// Register
app.post('/api/register', async (req,res)=>{
  const {username,password} = req.body;
  if(!username || !password) return res.status(400).json({error:'missing'});
  const now = Date.now();
  DB.get('SELECT id FROM users WHERE username=?',[username], async (err,row)=>{
    if(row) return res.status(400).json({error:'username_taken'});
    const hash = await bcrypt.hash(password,10);
    const initialAccount = {coins:0, highest:0, ownedSkins:['red'], selectedSkin:'red',
      difficulty:'medium', lives:1, totalScore:0, vipExpiry:0,
      achievements:{}, stats:{}, dailyChallenges:{}};
    DB.run(`INSERT INTO users(username,passwordHash,accountJson,createdAt,updatedAt) VALUES (?,?,?,?,?)`,
      [username,hash,JSON.stringify(initialAccount),now,now],
      function(err2){
        if(err2) return res.status(500).json({error:err2.message});
        const token=createToken({uid:this.lastID,username});
        res.json({token,account:initialAccount});
      });
  });
});

// Login
app.post('/api/login',(req,res)=>{
  const {username,password}=req.body;
  DB.get('SELECT * FROM users WHERE username=?',[username], async (err,row)=>{
    if(!row) return res.status(400).json({error:'no_user'});
    const ok=await bcrypt.compare(password,row.passwordHash);
    if(!ok) return res.status(401).json({error:'bad_credentials'});
    const token=createToken({uid:row.id,username});
    res.json({token,account:safeParseAccount(row.accountJson)});
  });
});

// Account
app.get('/api/account',authMiddleware,(req,res)=>{
  DB.get('SELECT accountJson FROM users WHERE id=?',[req.user.uid],(err,row)=>{
    if(err) return res.status(500).json({error:err.message});
    res.json({account:safeParseAccount(row.accountJson)});
  });
});

// Sync
app.post('/api/sync',authMiddleware,(req,res)=>{
  DB.run('UPDATE users SET accountJson=?,updatedAt=? WHERE id=?',
    [JSON.stringify(req.body.account||{}),Date.now(),req.user.uid],
    function(err){ if(err) return res.status(500).json({error:err.message}); res.json({ok:true}); });
});

// Leaderboard
app.get('/api/leaderboard',(req,res)=>{
  DB.all('SELECT username, json_extract(accountJson,"$.highest") as highest FROM users ORDER BY highest DESC LIMIT 100',
    [],(err,rows)=>{
      if(err) return res.status(500).json({error:err.message});
      res.json({leaderboard:rows.map(r=>({name:r.username,score:Number(r.highest||0)}))});
    });
});

// Password reset request
app.post('/api/request-reset',(req,res)=>{
  const {username}=req.body;
  DB.get('SELECT id FROM users WHERE username=?',[username],(err,row)=>{
    if(!row) return res.status(400).json({error:'no_user'});
    const token=uuidv4(); const exp=Date.now()+1000*60*15;
    DB.run('INSERT INTO resets(token,userId,expiresAt) VALUES(?,?,?)',[token,row.id,exp]);
    res.json({resetToken:token,expiresAt:exp});
  });
});

// Password reset confirm
app.post('/api/reset-password',async (req,res)=>{
  const {token,newPassword}=req.body;
  DB.get('SELECT * FROM resets WHERE token=?',[token],async (err,row)=>{
    if(!row) return res.status(400).json({error:'bad_token'});
    if(Date.now()>row.expiresAt) return res.status(400).json({error:'expired'});
    const hash=await bcrypt.hash(newPassword,10);
    DB.run('UPDATE users SET passwordHash=? WHERE id=?',[hash,row.userId],function(err2){
      if(err2) return res.status(500).json({error:err2.message});
      DB.run('DELETE FROM resets WHERE token=?',[token]);
      res.json({ok:true});
    });
  });
});

// Ping
app.get('/api/ping',(req,res)=>res.json({ok:true,time:Date.now()}));

app.listen(PORT,()=>console.log("Strike server v2 running on",PORT));
