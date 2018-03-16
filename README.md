# edb_block_commands
edb_block_commands is an extension which helps restricting superuser to perform utility, DML and SELECT command.

This extension is only compatible with EDB Advanced Server and can be modified to work with PostgreSQL. Utility is tested with EDB Postgres version >= 10.0


This extension comes with following GUC for whitelist:

* edb_block_commands.su_alter_system_whitelist 
* edb_block_commands.su_copy_command_whitelist 
* edb_block_commands.su_copy_program_whitelist
* edb_block_commands.su_delete_command_whitelist
* edb_block_commands.su_edbldr_command_whitelist
* edb_block_commands.su_insert_command_whitelist
* edb_block_commands.su_log_statement_whitelist
* edb_block_commands.su_read_whitelist
* edb_block_commands.su_set_command_whitelist
* edb_block_commands.su_show_command_whitelist
* edb_block_commands.su_update_command_whitelist
* edb_block_commands.su_vacuum_analyze_command_whitelist
* edb_block_commands.su_whitelist
* edb_block_commands.su_write_whitelist

If user wants to allow specific commands for super user then he/she can list the name of super user in above mentioned GUC.
Names listed in su_whitelist will allow super user to execute any commands.

## Installation

1. Clone the repository using following command:
```
git clone https://github.com/vibhorkum/edb_block_commands
```
2. After cloning the repository, set the pg_config location in PATH variables
```
export PATH=/usr/edb/as9.6/bin:$PATH
```
3. Execute following commands as root to install the edb_block_commands:
```
make 
make install
```

## Usage

After setting, the GUC in postgresql.conf, user can reload the postgresql.conf file using one of the following command:
```
pg_ctl -D $PGDATA reload
```
OR
```
psql -c "SELECT pg_reload_conf();"
```

After reloading the conf, user can set session_preload_libraries for super user as given below:
```
ALTER USER superuser SET session_preload_libraries = '$libdir/edb_block_commands'
```


