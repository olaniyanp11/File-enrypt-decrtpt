// routes/index.js  (FULL ROUTER WITH AES + HYBRID RSA/AES + FLASH MESSAGES)

const express = require('express');
const router  = express.Router();
const User    = require('../models/User');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const authenticateToken      = require('../middlewares/checkLog');
const getUser                = require('../middlewares/getUser');
const redirectIfAuthenticated = require('../middlewares/redirect');

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const multer = require('multer');
const EncryptedFile = require('../models/EncryptedFile');

/* ────────────────────────────────────────────────────────── */
/*  UPLOAD CONFIG                                             */
/* ────────────────────────────────────────────────────────── */
const upload = multer({
  dest: path.join(__dirname, '../uploads/tmp'),
  limits: { fileSize: 10 * 1024 * 1024 },      // 10 MB max
});

/* ensure directories exist */
['../uploads/encrypted', '../uploads/decrypted', '../uploads/keys'].forEach(dir => {
  fs.mkdirSync(path.join(__dirname, dir), { recursive: true });
});

/* ────────────────────────────────────────────────────────── */
/*  ENCRYPTION / DECRYPTION HELPERS                           */
/* ────────────────────────────────────────────────────────── */

// AES‑256‑CBC encrypt
function encryptAES(inputPath, outputPath, key, iv) {
  return new Promise((resolve, reject) => {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    fs.createReadStream(inputPath)
      .pipe(cipher)
      .pipe(fs.createWriteStream(outputPath))
      .on('finish', resolve)
      .on('error', reject);
  });
}

// AES‑256‑CBC decrypt
function decryptAES(inputPath, outputPath, key, iv) {
  return new Promise((resolve, reject) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    fs.createReadStream(inputPath)
      .pipe(decipher)
      .pipe(fs.createWriteStream(outputPath))
      .on('finish', resolve)
      .on('error', reject);
  });
}

/* Hybrid encrypt: AES for file, RSA public key for AES key  */
async function hybridEncrypt(inputPath, outputPath, publicKeyPem) {
  const aesKey = crypto.randomBytes(32);
  const iv     = crypto.randomBytes(16);

  await encryptAES(inputPath, outputPath, aesKey, iv);

  const encryptedKey = crypto.publicEncrypt(publicKeyPem, aesKey);
  return { encryptedKey, iv };
}

router.get('/', getUser, (req, res) =>
  res.render('index', { title: 'Home', user: req.user || null })
);

router.get('/register',  redirectIfAuthenticated,getUser,(req, res) => res.render('register', { title: 'Register', user: req.user })
);

router.get('/login',redirectIfAuthenticated,getUser,(req, res) => res.render('login', { title: 'Login', user: req.user })
);
router.get('/encrypt', getUser, authenticateToken,(req, res) => res.render('protected/encrypt', { title: 'Encrypt', user: req.user })
);


router.get('/decrypt', getUser, authenticateToken,(req, res) => res.render('protected/decrypt', { title: 'Decrypt', user: req.user })
);

router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (await User.findOne({ email })) {
      req.flash('error', 'Email already exists.');
      return res.redirect('/register');
    }
    if (password.length < 6) {
      req.flash('error', 'Password must be at least 6 characters.');
      return res.redirect('/register');
    }
    const hashed = await bcrypt.hash(password, 10);
    await new User({ name, email, password: hashed }).save();
    req.flash('success', 'Account created. Please login.');
    res.redirect('/login');
  } catch (e) {
    console.error(e);
    req.flash('error', 'Registration failed.');
    res.redirect('/register');
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      req.flash('error', 'Invalid email or password.');
      return res.redirect('/login');
    }
    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    req.flash('success', 'Welcome back!');
    res.redirect('/encrypt');
  } catch (e) {
    console.error(e);
    req.flash('error', 'Login error.');
    res.redirect('/login');
  }
});
router.post('/encrypt',
  getUser, authenticateToken, upload.single('document'),
  async (req, res) => {
    const file = req.file;
    const method = req.body.method;

    if (!file) {
      req.flash('error', 'No file uploaded.');
      return res.redirect('/encrypt');
    }

    const inputPath = file.path;
    const outName   = `${Date.now()}-${file.originalname}.enc`;
    const encryptedPath = path.join(__dirname, '../uploads/encrypted', outName);

    try {
      let fileDoc, keyData;

      if (method === 'aes') {
        const aesKey = crypto.randomBytes(32);
        const iv     = crypto.randomBytes(16);

        await encryptAES(inputPath, encryptedPath, aesKey, iv);

        fileDoc = await EncryptedFile.create({
          originalName: file.originalname,
          storagePath : encryptedPath,
          method      : 'aes',
          uploadedBy  : req.user._id
        });

        keyData = {
          fileId: fileDoc._id,
          method: 'aes',
          key   : aesKey.toString('base64'),
          iv    : iv.toString('base64')
        };
      }

      else if (method === 'rsa') {
        // Generate RSA key pair
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        });

        const aesKey = crypto.randomBytes(32);
        const iv     = crypto.randomBytes(16);

        await encryptAES(inputPath, encryptedPath, aesKey, iv);

        const encryptedKey = crypto.publicEncrypt(publicKey, aesKey);

        fileDoc = await EncryptedFile.create({
          originalName: file.originalname,
          storagePath : encryptedPath,
          method      : 'rsa',
          uploadedBy  : req.user._id
        });

        keyData = {
          fileId       : fileDoc._id,
          method       : 'rsa',
          encryptedKey : encryptedKey.toString('base64'),
          iv           : iv.toString('base64'),
          privateKey   : privateKey // not base64 encoded — it's PEM text
        };
      }

      else {
        req.flash('error', 'Invalid encryption method.');
        return res.redirect('/encrypt');
      }

      const keyPath = path.join(__dirname, '../temp', `${fileDoc._id}.key.json`);
      fs.writeFileSync(keyPath, JSON.stringify(keyData));

      req.flash('success', 'File encrypted successfully. Save your key file.');
      return res.redirect(`/success?keyId=${fileDoc._id}`);

    } catch (err) {
      console.error(err);
      req.flash('error', 'Encryption failed.');
      res.redirect('/encrypt');
    }
  }
);


/* ─────────────────────────────────────────────────── */
/*  POST /decrypt                                      */
/* ─────────────────────────────────────────────────── */
router.post('/decrypt',
  getUser, authenticateToken, upload.single('keyInfo'),
  async (req, res) => {
    const keyFile = req.file;
    if (!keyFile) {
      req.flash('error', 'Key file is required.');
      return res.redirect('/decrypt');
    }

    try {
      const keyData = JSON.parse(fs.readFileSync(keyFile.path, 'utf8'));
      const fileId = keyData.fileId;
      if (!fileId) throw new Error('Invalid key file: missing fileId.');

      const fileDoc = await EncryptedFile.findById(fileId);
      if (!fileDoc) throw new Error('Encrypted file not found.');

      // Ensure only the uploader can decrypt
      if (fileDoc.uploadedBy.toString() !== req.user._id.toString()) {
req.flash('error', 'You are not authorized to decrypt this file.');
      return res.redirect('/decrypt');
      }

      const decryptedDir = path.join(__dirname, '../uploads/decrypted');
      if (!fs.existsSync(decryptedDir)) fs.mkdirSync(decryptedDir, { recursive: true });

      const decryptedName = fileDoc.originalName;
      const decryptedPath = path.join(decryptedDir, `${Date.now()}-${decryptedName}`);

      let aesKey;
      const iv = Buffer.from(keyData.iv, 'base64');

      if (keyData.method === 'aes') {
        aesKey = Buffer.from(keyData.key, 'base64');
      } else if (keyData.method === 'rsa') {
        const encryptedKey = Buffer.from(keyData.encryptedKey, 'base64');
        const privateKey = keyData.privateKey;
        aesKey = crypto.privateDecrypt(privateKey, encryptedKey);
      } else {
        throw new Error('Unsupported decryption method.');
      }

      await decryptAES(fileDoc.storagePath, decryptedPath, aesKey, iv);

      fileDoc.decryptedPath = decryptedPath;
      await fileDoc.save();

      req.flash('success', 'File decrypted successfully.');
      res.redirect(`/success?fileId=${fileDoc._id}`);

    } catch (err) {
      console.error(err);
      return req.flash('error', 'Decryption failed. Invalid key or file.');
      return res.redirect('/decrypt');
    }
  }
);

/* ─────────────────────────────────────────────────── */
/*  GET /success                                        */
/* ─────────────────────────────────────────────────── */
router.get('/success',
  getUser, authenticateToken,
  (req, res) => {
    const { keyId, fileId } = req.query;
    res.render('success', {
      keyId   : keyId || null,
      fileId  : fileId || null,
      messages: req.flash(),
      user:req.user, title:"success"
    });
  });

/* ─────────────────────────────────────────────────── */
/*  GET /download/:fileId                              */
/* ─────────────────────────────────────────────────── */
router.get('/download/:fileId',
  getUser, authenticateToken,
  async (req, res) => {

    try {
      const fileDoc = await EncryptedFile.findById(req.params.fileId);
      if (!fileDoc || !fileDoc.decryptedPath || !fs.existsSync(fileDoc.decryptedPath)) {
        req.flash('error', 'Decrypted file not available.');
        return res.redirect('/decrypt');
      }

      /* Stream file; delete afterwards (optional) */
      res.download(fileDoc.decryptedPath, fileDoc.originalName, () => {
        // 🔒 optional clean‑up
        fs.unlinkSync(fileDoc.decryptedPath);
        fileDoc.decryptedPath = undefined;
        fileDoc.save();
      });

    } catch (err) {
      console.error(err);
      req.flash('error', 'Download failed.');
      res.redirect('/');
    }
  });

/* ─────────────────────────────────────────────────── */
/*  GET /download-key/:keyId                           */
/* ─────────────────────────────────────────────────── */
router.get('/download-key/:keyId',
  getUser, authenticateToken,
  (req, res) => {
    const keyPath = path.join(__dirname, '../temp', `${req.params.keyId}.key.json`);
    if (fs.existsSync(keyPath)) {
      return res.download(keyPath, `${req.params.keyId}.key.json`);
    }
    req.flash('error', 'Key file not found.');
    res.redirect('/');
  });
  router.get('/logout', (req, res) => {
  res.clearCookie('token');
  req.flash('success', 'You have been logged out.');
  res.redirect('/login');
});
module.exports = router;