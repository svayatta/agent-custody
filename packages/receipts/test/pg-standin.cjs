// Preloaded into the CLI by a test (node --require): the `pg` package becomes a Pool on a PGlite directory, so that a
// log-admin command runs against a real database without a Postgres server. The directory comes from PG_STANDIN_DIR.
const Module = require("node:module");
const { PGlite } = require("@electric-sql/pglite");

const db = new PGlite(process.env.PG_STANDIN_DIR);
const load = Module._load;
Module._load = function (request, ...rest) {
  if (request !== "pg") return load.call(this, request, ...rest);
  return {
    Pool: class {
      async query(sql, params) {
        const result = await db.query(sql, params);
        await db.syncToFs();
        return result;
      }
    },
  };
};
