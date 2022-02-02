const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../config/keys');
const errorHendler = require('../utils/errorHandler');

module.exports.login = async function (req, res) {
    const canditat = await User.findOne({email: req.body.email})

    if (canditat){
        //stugel pass@, emeail ka
        const passwordResult = bcrypt.compareSync(req.body.password, canditat.password)
        if (passwordResult){
            //generacnel token, parol@ chisht e

            const token = jwt.sign({
                email: canditat.email,
                userId: canditat._id
            }, keys.jwt, {expiresIn: 60 * 60});

            res.status(200).json({
                token: token
            })
        }else{
            //passer@ chi hamnknum
            res.status(401).json({
                message: "passwords doesn't match"
            })
        }
    }else{
        //user chka , error
        res.status(404).json({
            message: 'there is no such user with such an email'
        })
    }
}

module.exports.register = async function (req, res) {
    //email //password

    const canditat = await User.findOne({email: req.body.email})
    if (canditat){
        // user@ ka
        res.status(409).json({
            message: 'email is busy'
        })
    }else{
        //stexcel user
        const salt = bcrypt.genSaltSync(10)
        const password = req.body.password
        const user = new User({
            email: req.body.email,
            password: bcrypt.hashSync(password, salt)
        })
        try {
            await user.save()
            res.status(201).json(user)
        }catch (e) {
            // error
            errorHendler(res, e)
        }

    }
}
