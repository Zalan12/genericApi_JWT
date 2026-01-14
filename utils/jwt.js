var jwt = require('jsonwebtoken');
const logger=require('./logger');

function ensureSecret()

{
    if(!process.env.ACCESS_TOKEN_SECRET)
        {
            const message='Az ACCESS_TOKEN_SECRET nnincs beállítva a környzeti változók között.'
            logger.error(message)
            throw new Error();
        }
    
    return process.env.ACCESS_TOKEN_SECRET;
}

function generateToken(payload){
    const secret=ensureSecret()
    return jwt.sign(payload, secret);
}

function verityToken(token)
{   
     const secret=ensureSecret()
    return jwt.verify(token,secret);
}

function authenticate(req,res,next){
    const authHeader=req.headers.authorization || '';    
    const token=authHeader.split(' ')[1];

    if(!token)
    {
        return res.status(401).json({error:"Hiányzó vagy érvénytelen token"})
    }

    try{
        req.user=verityToken(token);
        next();
    }
    catch(err)
    {
        logger.error('JWT ellenőrzés sikertelen!',{error:"Érvénytelen / lejárt token"})
        return res.status(401).json({error:"Érvénytelen / lejárt token"})
    }
    
}

module.exports={
    generateToken,
    verityToken,
    authenticate
}