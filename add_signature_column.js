require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function addSignatureColumn() {
  try {
    console.log("Connecting to the database...");
    
    // Add the signature column. It allows NULLs for legacy certificates.
    await pool.query(`
      ALTER TABLE certificates 
      ADD COLUMN IF NOT EXISTS signature VARCHAR(255);
    `);
    
    console.log("✅ Successfully added 'signature' column to the certificates table!");
  } catch (err) {
    console.error("❌ Error modifying table:", err);
  } finally {
    await pool.end();
  }
}

addSignatureColumn();