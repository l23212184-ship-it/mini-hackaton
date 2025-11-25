const bcrypt = require("bcrypt");

bcrypt.hash("1234", 10).then((hash) => {
  console.log("HASH GENERADO:", hash);
  process.exit(0);
});
