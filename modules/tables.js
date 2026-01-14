const express = require('express');
const router = express.Router();
const { query } = require('../utils/database');
const logger = require('../utils/logger');
const { error } = require('winston');
const passwdRegExp = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
var SHA1 = require("crypto-js/sha1");
const multer=require('multer');
const nodemailer = require("nodemailer");
const path=require('path');
const fs=require('fs');
let ejs=require('ejs');


const {generateToken,verityToken,authenticate} =require('../utils/jwt')


var transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

//Select All records
router.get('/:table',authenticate, (req, res) => {
  const table = req.params.table;
  query(`SELECT * FROM ${table}`, [], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req);
})
//Select one record from table by id
router.get('/:table/:id', (req, res) => {
  const table = req.params.table;
  const id = req.params.id;
  query(`SELECT * FROM ${table} WHERE id=?`, [id], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req);
})

//Select one record from table by userId
router.get('/:table/user/:userId', (req, res) => {
  const table = req.params.table;
  const userId = req.params.userId;
  query(`SELECT 
    p.name AS pizza_nev,
    o.status AS rendeles_statusz,
    o.total AS rendeles_ara,
    o.created_at AS kelt,
    oi.quantity AS mennyiseg,
    p.description AS leiras
FROM order_items oi
JOIN orders o ON oi.order_id = o.id
JOIN pizzas p ON oi.pizza_id = p.id
WHERE o.user_id = ?`, [userId], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req);
})


//SENDING email

router.post('/sendemail',async(req,res)=>{
  const{to, subject, template, data}=req.body;
  if(!to||!subject||!template){
    return res.status(400).send({error:"Hiányzó adatok!"})
}

try{
  await transporter.sendMail({
    from:process.env.ADMINMAIL,
    to:to,
    subject:subject,
    html:await renderTemplate(template,data|| {}),
  })

  return res.status(200).send({message:"Az email küldése sikeres!"})
}
catch(err){
  console.log(err);
  return res.status(500).send({error:"Hiba z email kulesekor"})
}

});


//Select one record from table by id
router.get('/:table/email', (req, res) => {
  const table = req.params.table;
  const email = req.params.email;
  query(`SELECT * FROM ${table} WHERE email=?`, [email], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req);
})

//SELECT record by :field
router.get('/:table/:field/:op/:value',(req,res)=>{

  let table=req.params.table;
  let field=req.params.field;
  let op=getOp(req.params.op);
  let value=req.params.value;

  if(req.params.op=='lk'){
    value=`%${value}%`;
  }
  query(`SELECT * FROM ${table} WHERE ${field}${op}?`, [value], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req);

})

//LOGIN (post)
router.post('/:table/login', (req, res) => {
  let { email, password } = req.body;
  let table = req.params.table;
  //TODO: vali-dalas

  if (!email || !password) {
    res.status(400).send({ error: 'Hiányzó data!' });
    return;
  }

  query(`SELECT * FROM ${table} WHERE email=? AND password=?`, [email, SHA1(password).toString()], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    if (results.length == 0) {
      res.status(400).send({ error: 'Hibás belépési adatok!' })
      return;
    }

    let token=generateToken(JSON.stringify(results[0]));
    res.status(200).json({token});
  }, req);
})

//REGISTRATION (post)
router.post('/:table/registration', (req, res) => {
  let table = req.params.table;
  let { name, email, password, confirm } = req.body;

  //TODO: vali-dalas

  if (!name | !email | !password | !confirm) {
    res.status(400).send({ error: 'Hiányzó data!' });
    return;
  }
  if (password != confirm) {
    res.status(400).send({ error: 'A megadott jelszavak nem egyeznek!' })
  }
  if (!password.match(passwdRegExp)) {

    res.status(400).send({ error: 'Nem eleg eros jelszo!' })
  }



  query(`INSERT INTO ${table} (name,email,password,role) VALUES(?,?,?,'user')`, [name, email, SHA1(password).toString()], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });

    res.status(200).json(results);
  }, req)
})

//POST record to :table 

router.post('/:table', (req, res) => {
  let table = req.params.table;
  let fields = Object.keys(req.body);
  let values = "'" + Object.values(req.body).join("','") + "'";
  console.log(fields)
  query(`INSERT INTO ${table} (${fields}) VALUES(${values})`, [], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req)
})
//UPDATE records in:table by :id
router.patch('/:table/:id', (req, res) => {
  let table = req.params.table;
  let id = req.params.id;
  let fields = Object.keys(req.body);
  let values = Object.values(req.body);

  let updates = [];
  for (let i = 0; i < fields.length; i++) {
    updates.push(`${fields[i]}='${values[i]}'`)
  }
  let str = updates.join(',');
  query(`UPDATE ${table} SET ${str} WHERE id=?`, [id], (error, results) => {
    if (error) return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    res.status(200).json(results);
  }, req)
})


/*
    //insert one record to table
router.post('/:table', (req, res) => {
  const table = req.params.table;
  const data = req.body; 

  if (!data || Object.keys(data).length === 0) {
    return res.status(400).json({ msg: 'Nincs adat a body-ban!' });
  }

 
  const columns = Object.keys(data);
  const placeholders = columns.map(() => '?').join(', ');
  const values = Object.values(data);

  const sql = `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`;

  query(sql, values, (error, results) => {
    if (error) {
      logger.error(error);
      return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    }
    res.status(200).json({ msg: 'Sikeres beszúrás!', insertId: results.insertId });
  }, req);
});

// Delete one record by id
router.delete('/:table/:id', (req, res) => {
  const table = req.params.table;
  const id = req.params.id;

  if (!id) {
    return res.status(400).json({ msg: 'Hiányzik az id paraméter!' });
  }

  const sql = `DELETE FROM ${table} WHERE id = ?`;

  query(sql, [id], (error, results) => {
    if (error) {
      logger.error(error);
      return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ msg: 'Nem található ilyen rekord.' });
    }

    res.status(200).json({ msg: 'Sikeresen törölve!' });
  }, req);
});


// Update (partial) record by id
router.patch('/:table/:id', (req, res) => {
  const table = req.params.table;
  const id = req.params.id;
  const data = req.body;

  if (!id) {
    return res.status(400).json({ msg: 'Hiányzik az id paraméter!' });
  }

  if (!data || Object.keys(data).length === 0) {
    return res.status(400).json({ msg: 'Nincs adat a body-ban!' });
  }

  
  const columns = Object.keys(data);
  const values = Object.values(data);
  const setClause = columns.map(col => `${col} = ?`).join(', ');

  const sql = `UPDATE ${table} SET ${setClause} WHERE id = ?`;

  query(sql, [...values, id], (error, results) => {
    if (error) {
      logger.error(error);
      return res.status(500).json({ errno: error.errno, msg: 'Baj van geco' });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ msg: 'Nem található ilyen rekord.' });
    }

    res.status(200).json({ msg: 'Sikeres frissítés!' });
  }, req);
});
*/

function getOp(op){
  switch(op){
    case 'eq':{op='=';break}
    case 'lt':{op='<';break}
    case 'lte':{op='<=';break}
    case 'gt':{op='>';break}
    case 'gte':{op='>=';break}
    case 'not':{op='<>';break}
    case 'lk':{op=' like ';break}
  }
  return op;
}

async function renderTemplate(templateName,data)
{
    const tmpFile= path.join(__dirname,"..","templates",templateName +'.ejs')
    return await ejs.renderFile(tmpFile,data);
  }

module.exports = router;

