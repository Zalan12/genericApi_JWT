const express = require('express');
var cors = require('cors');

const logger=require('./utils/logger')
const tables=require('./modules/tables')
const app=express()



app.use(cors());
app.use(express.json());  // json formátum megkövetelése
app.use(express.urlencoded({ extended: true })); // req body-n keresztül átmenjenek az adatok


app.use('/',tables)


app.listen(process.env.PORT, ()=>{
    logger.info(`Server listening on http://localhost:${process.env.PORT}`);
});
