// models/EncryptedFile.js
const mongoose = require('mongoose');

const EncryptedFileSchema = new mongoose.Schema({
  originalName:  String,
  storagePath:   String,   // path to encrypted .enc file
  decryptedPath: String,   // path to decrypted file (filled after decrypt)
  method:        String,   // 'aes' for now
  uploadedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt:     { type: Date, default: Date.now }
});

module.exports = mongoose.model('EncryptedFile', EncryptedFileSchema);
