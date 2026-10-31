// Usage: npm run hash-password -- "your new password"
// Copy the printed line into your .env file as ADMIN_PASS_HASH=...
import crypto from "node:crypto";

const pass = process.argv[2];
if (!pass) { console.error('Usage: npm run hash-password -- "your new password"'); process.exit(1); }
const salt = crypto.randomBytes(16).toString("hex");
console.log(`ADMIN_PASS_HASH=scrypt$${salt}$${crypto.scryptSync(pass, salt, 64).toString("hex")}`);
