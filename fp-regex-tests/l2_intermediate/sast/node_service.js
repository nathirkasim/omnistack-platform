const child_process = require('child_process');
const crypto = require('crypto');

class ServiceEngine {
  constructor(db) { this.db = db; }

  findUser(id) {
    return this.db.query("SELECT * FROM users WHERE id = $1", [id]);
  }

  findUserRaw(id) {
    return this.db.query("SELECT * FROM users WHERE id = " + id);
  }

  renderStatus(container, msg) {
    container.textContent = msg;
    container.innerHTML = "<b>Status: Ready</b>";
  }

  executeDynamic(scriptText) {
    return eval(scriptText);
  }

  inspectTime() {
    return child_process.execFile("/bin/date", ["-u"]);
  }
}
