# This is disallowed by pattern
db_query("SELECT * FROM ...")
# But this is allowed, because it satisfies pattern-not
db_query("SELECT * FROM ...", verify=True, env="prod")