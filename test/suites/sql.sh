# Test the lxd sql command.
test_sql() {
  # Invalid arguments
  ! lxd sql
  ! lxd sql foo "SELECT * FROM CONFIG"
  ! lxd sql global ""

  # Local database query
  lxd sql local "SELECT * FROM config" | grep -q "core.https_address"

  # Global database query
  lxd sql global "SELECT * FROM config" | grep -q "core.trust_password"

  # Global database insert
  lxd sql global "INSERT INTO config(key,value) VALUES('core.https_allowed_credentials','true')" | grep -q "Rows affected: 1"
  lxd sql global "DELETE FROM config WHERE key='core.https_allowed_credentials'" | grep -q "Rows affected: 1"

  # Standard input
  echo "SELECT * FROM config" | lxd sql global - | grep -q "core.trust_password"

  # Multiple queries
  lxd sql global "SELECT * FROM config; SELECT * FROM containers" | grep -q "=> Query 0"

  # Local database dump
  SQLITE_DUMP="${TEST_DIR}/dump.db"
  lxd sql local dump | sqlite3 "${SQLITE_DUMP}"
  sqlite3 "${SQLITE_DUMP}" "SELECT * FROM patches" | grep -q invalid_profile_names
  rm -f "${SQLITE_DUMP}"

  # Global database dump
  SQLITE_DUMP="${TEST_DIR}/dump.db"
  lxd sql global dump | sqlite3 "${SQLITE_DUMP}"
  sqlite3 "${SQLITE_DUMP}" "SELECT * FROM profiles" | grep -q "Default LXD profile"
  rm -f "${SQLITE_DUMP}"
}
