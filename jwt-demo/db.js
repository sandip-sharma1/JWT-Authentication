// Stores everything in a JSON file. Rewrites the whole thing on every change and
// has no locking, so it would fall over under any real load, but it keeps accounts
// and sessions around between restarts without adding a database dependency.
const fs = require("fs");
const path = require("path");

const FILE = path.join(__dirname, "data.json");

const EMPTY = { users: [], notes: [], sessions: [], nextUserId: 1, nextNoteId: 1 };

function load() {
  try {
    return { ...EMPTY, ...JSON.parse(fs.readFileSync(FILE, "utf8")) };
  } catch {
    return { ...EMPTY }; // first run, or the file is unreadable
  }
}

const db = load();

// Write to a temp file and rename, so a crash halfway through can't leave a
// truncated data.json behind.
function save() {
  const tmp = FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, FILE);
}

module.exports = { db, save };
