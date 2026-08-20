// A tiny JSON-file "database".
//
// Not what you'd use in production (no concurrency control, rewrites the whole
// file on every change), but it makes accounts and sessions survive a restart
// without pulling in a native dependency.
const fs = require("fs");
const path = require("path");

const FILE = path.join(__dirname, "data.json");

const EMPTY = { users: [], notes: [], sessions: [], nextUserId: 1, nextNoteId: 1 };

function load() {
  try {
    return { ...EMPTY, ...JSON.parse(fs.readFileSync(FILE, "utf8")) };
  } catch {
    return { ...EMPTY }; // first run, or the file got corrupted
  }
}

const db = load();

// Write to a temp file then rename: a crash mid-write can't leave a half-written
// data.json behind, because rename is atomic on POSIX.
function save() {
  const tmp = FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, FILE);
}

module.exports = { db, save };
