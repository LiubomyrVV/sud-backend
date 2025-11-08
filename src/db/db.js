const sql = require('mssql');
require('dotenv').config();

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_HOST,
  database: process.env.DB_NAME, 
  port: Number(process.env.DB_PORT),
  options: {
    encrypt: process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: process.env.DB_TRUST_SERVER_CERT === 'true',
  },
};

const pool = new sql.ConnectionPool(config);
const poolConnect = pool.connect().then(() => {
  console.log('Connected to SQL Server');
}).catch(err => {
  console.error('Database Connection Failed! Bad Config: ', err);
})




async function query(sqlText, params = {}) {
  await poolConnect;
  const request = pool.request();
  for (const [name, value] of Object.entries(params)) {
    request.input(name, value);
  }
  const result = await request.query(sqlText);
  return result.recordset;
}

module.exports = { query };
