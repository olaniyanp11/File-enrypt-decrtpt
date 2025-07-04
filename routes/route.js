const express = require('express');
const authRoutes = require('./auth');
const userRoute = require('./user')
const router = express.Router();

router.use("/",authRoutes)
router.use("/user",authRoutes)


module.exports = router;