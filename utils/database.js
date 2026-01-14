var mysql = require('mysql');
const logger = require('./logger')
require('dotenv').config();


var pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DBHOST,
  user: process.env.DBUSER,
  password: process.env.DBPASS,
  database: process.env.DBNAME
});

function query(sql, params = [], callback, req = '') {
  const start = Date.now();
  const context = req ? `${req.method} ${req.originalUrl}` : `NO CONTEXT`
  const txt = req.method == 'GET' ? 'Sent' : 'affected'
  pool.query(sql, params, (error, results) => {
    if(process.env.DEBUG==1){
    const duration = Date.now() - start;
    if (error) {
      logger.error(`[DB error]: ${error.message}`)
    }
    else {
      const count = Array.isArray(results) ? results.length : results.affectedRows;

      logger.info(`${context} - ${count} record(s) ${txt} | ${duration}ms`)
    }
    if (callback) callback(error, results);
  }})
}

module.exports = { query };