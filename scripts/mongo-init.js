// mongo-init.js
// Initialize MongoDB with verichain database and user.

db = db.getSiblingDB('verichain');

db.createUser({
  user: 'verichain_user',
  pwd: 'verichain_password',
  roles: [
    {
      role: 'readWrite',
      db: 'verichain',
    },
  ],
});

db.createCollection('audit_logs');
db.collection('audit_logs').createIndex({ timestamp: 1 });
db.collection('audit_logs').createIndex({ userHash: 1 });
db.collection('audit_logs').createIndex({ anchored: 1 });

console.log('MongoDB initialized successfully');
