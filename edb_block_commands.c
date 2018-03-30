/*-------------------------------------------------------------------------
 *
 * edb_block_commands.c
 *		Extension control which commands are allowed by specifc 
 *		user..
 *
 * Copyright (c) 1996-2018, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  edb_block_commands/edb_block_commands.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "executor/spi.h"
#include "fmgr.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/snapmgr.h"
#include "pg_config.h"
#if !defined(PG_VERSION_NUM) || PG_VERSION_NUM < 90600
/* prior to 9.1 */
#error "This extension only builds with PostgreSQL 9.6 or later"
#elif PG_VERSION_NUM < 100000
/* 9.6 */
#define HAS_HTUP_DETAILS
#define HAS_ALTER_SYSTEM
#define HAS_COPY_PROGRAM
#define HAS_TWO_ARG_GETUSERNAMEFROMID
#define HAS_PROCESSUTILITYCONTEXT
#define HAS_LOAD_ROW_DATA

#else
/* master */
#define HAS_HTUP_DETAILS
#define HAS_ALTER_SYSTEM
#define HAS_COPY_PROGRAM
#define HAS_TWO_ARG_GETUSERNAMEFROMID
#define HAS_PROCESSUTILITYCONTEXT
#define HAS_PSTMT
#define HAS_VARLENA_H

#endif
#include "access/xact.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include "parser/analyze.h"

#define WHITELIST_WILDCARD	"*"

#ifdef HAS_VARLENA_H
#include "utils/varlena.h"
#endif /* HAS_VARLENA_H */

PG_MODULE_MAGIC;

/*--- Functions --- */

void	_PG_init(void);
void	_PG_fini(void);

static ProcessUtility_hook_type prev_utility_hook = NULL;
static post_parse_analyze_hook_type original_post_parse_analyze_hook = NULL;

/* Parameters which controls what is allowed 
 * by a specific user
 */

static bool disallow_delete = true;
static bool disallow_update = true;
static bool disallow_insert = true;
static bool disallow_select = true;
static bool disallow_show_command = true;
static bool disallow_write  = true;
static bool disallow_copy_program = true;
static bool disallow_copy_command = true;
static bool disallow_log_statement = true;
static bool disallow_set_statement = true;
static bool disallow_alter_system = true;
static bool disallow_edbldr = true;
static bool disallow_vacuum_analyze = true; 

/* whitelist superuser 
 * parameters
 */

static char *save_log_statement = NULL;
static Oid save_OldUserId = InvalidOid;
static char *reset_token = NULL;

/* white list is short named as wlist
 */

static char *su_wlist = NULL;
static char *su_alter_system_wlist = NULL;
static char *su_copy_command_wlist = NULL;
static char *su_copy_program_wlist = NULL;
static char *su_log_statement_wlist = NULL;
static char *su_show_wlist = NULL;
static char *su_set_wlist = NULL;
static char *su_vacuum_analyze_wlist = NULL;
static char *su_edbldr_wlist = NULL;
static char *su_delete_wlist = NULL;
static char *su_insert_wlist = NULL;
static char *su_update_wlist = NULL;
static char *su_read_wlist = NULL;
static char *su_write_wlist = NULL;

#ifdef HAS_TWO_ARG_GETUSERNAMEFROMID
/* 9.5 - master */
#define GETUSERNAMEFROMID(ouserid) GetUserNameFromId(ouserid, false)
#else
/* 9.1 - 9.4 */
#define GETUSERNAMEFROMID(ouserid) GetUserNameFromId(ouserid)
#endif


PG_FUNCTION_INFO_V1(edb_switch_user);
Datum
edb_switch_user(PG_FUNCTION_ARGS)
{
	bool			argisnull = PG_ARGISNULL(0);
	int				nargs = PG_NARGS();
	HeapTuple		roleTup;
	Oid				OldUserId = GetUserId();
	char		   *olduser = GETUSERNAMEFROMID(OldUserId);
	bool			OldUser_is_superuser = superuser_arg(OldUserId);
	Oid				NewUserId = InvalidOid;
	char		   *newuser = NULL;
	bool			NewUser_is_superuser = false;
	char		   *su = "Superuser ";
	char		   *nsu = "";
	MemoryContext	oldcontext;
	bool			is_reset = false;
	bool			is_token = false;
	bool			is_privileged = false;

	/*
  	 * Disallow SET ROLE inside a transaction block. The
  	 * semantics are too strange, and I cannot think of a
 	 * good use case where it would make sense anyway.
  	 * Perhaps one day we will need to rethink this...
  	 */
	if (IsTransactionBlock())
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						errmsg("edb_block_commands: SET ROLE not allowed within transaction block"),
						errhint("Use SET ROLE outside transaction block instead.")));

	/*
  	 * edb_switch_user(non_null_arg text)
  	 *
  	 * Might be edb_switch_user(username) but might also be edb_switch_user(reset_token).
  	 * The former case we need to switch user normally, the latter is a
  	 * reset with token provided. We need to determine which one we have.
  	 */
	if (nargs == 1 && !argisnull)
	{
		Oid				funcOid = fcinfo->flinfo->fn_oid;
		HeapTuple		procTup;
		Form_pg_proc	procStruct;
		char		   *funcname;

		/* Lookup the pg_proc tuple by Oid */
		procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcOid));
		if (!HeapTupleIsValid(procTup))
			elog(ERROR, "cache lookup failed for function %u", funcOid);
		procStruct = (Form_pg_proc) GETSTRUCT(procTup);
		funcname = pstrdup(NameStr(procStruct->proname));
		ReleaseSysCache(procTup);

		if (strcmp(funcname, "reset_user") == 0)
		{
			is_reset = true;
			is_token = true;
		}

		if (strcmp(funcname, "edb_switch_user_u") == 0)
			is_privileged = true;
	}
	/*
  	 * edb_switch_user() or edb_switch_user(NULL) ==> always a reset
  	 */
	else if (nargs == 0 || (nargs == 1 && argisnull))
		is_reset = true;

	if ((nargs == 1 && !is_reset) || nargs == 2)
	{
		/* we are setting a new user */
		if (save_OldUserId != InvalidOid)
			elog(ERROR, "must reset previous user prior to setting again");

		newuser = text_to_cstring(PG_GETARG_TEXT_PP(0));

		/* with 2 args, the caller wants to specify a reset token */
		if (nargs == 2)
		{
			/* use session lifetime memory */
			oldcontext = MemoryContextSwitchTo(TopMemoryContext);
			/* capture the reset token */
			reset_token = text_to_cstring(PG_GETARG_TEXT_PP(1));
			MemoryContextSwitchTo(oldcontext);
		}

		/* Look up the username */
		roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum(newuser));
		if (!HeapTupleIsValid(roleTup))
			elog(ERROR, "role \"%s\" does not exist", newuser);

		NewUserId = HeapTupleGetOid(roleTup);
		NewUser_is_superuser = ((Form_pg_authid) GETSTRUCT(roleTup))->rolsuper;
		ReleaseSysCache(roleTup);

		if (NewUser_is_superuser)
		{
			if (!is_privileged)
				/* can only escalate with edb_switch_user_u */
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("switching to superuser not allowed"),
						 errhint("Use \'edb_switch_user_u\' to escalate.")));
		}

		/* keep track of original userid and value of log_statement */
		save_OldUserId = OldUserId;
		oldcontext = MemoryContextSwitchTo(TopMemoryContext);
		save_log_statement = pstrdup(GetConfigOption("log_statement",
													 false, false));
		MemoryContextSwitchTo(oldcontext);

		/*
 		 * Force logging of everything if block_log_statement is true
  		 * and we are escalating to superuser. If not escalating to superuser
  		 * the caller could always set log_statement to all prior to using
  		 * set_user, and ensure disallow_log_statement is true.
  		 */
		if (NewUser_is_superuser && disallow_log_statement)
			SetConfigOption("log_statement", "all", PGC_SUSET, PGC_S_SESSION);
	}
	else if (is_reset)
	{
		char	   *user_supplied_token = NULL;

		/* set_user not active, nothing to do */
		if (save_OldUserId == InvalidOid)
			PG_RETURN_TEXT_P(cstring_to_text("OK"));

		if (reset_token && !is_token)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("reset token required but not provided")));
		else if (reset_token && is_token)
			user_supplied_token = text_to_cstring(PG_GETARG_TEXT_PP(0));

		if (reset_token)
		{
			if (strcmp(reset_token, user_supplied_token) != 0)
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						errmsg("incorrect reset token provided")));
		}

		/* get original userid to whom we will reset */
		NewUserId = save_OldUserId;
		newuser = GETUSERNAMEFROMID(NewUserId);
		NewUser_is_superuser = superuser_arg(NewUserId);

		/* flag that we are now reset */
		save_OldUserId = InvalidOid;

		/* restore original log_statement setting if block_log_statement is true */
		if (disallow_log_statement)
			SetConfigOption("log_statement", save_log_statement, PGC_SUSET, PGC_S_SESSION);

		pfree(save_log_statement);
		save_log_statement = NULL;

		if (reset_token)
		{
			pfree(reset_token);
			reset_token = NULL;
		}
	}
	else
		/* should not happen */
		elog(ERROR, "unexpected argument combination");

	elog(LOG, "%sRole %s transitioning to %sRole %s",
			  OldUser_is_superuser ? su : nsu,
			  olduser,
			  NewUser_is_superuser ? su : nsu,
			  newuser);

	SetCurrentRoleId(NewUserId, NewUser_is_superuser);

	PG_RETURN_TEXT_P(cstring_to_text("OK"));
}

/*
 * edb_check_su_whitelist
 *
 * Check if user is contained by whitelist
 *
 */
static bool
edb_check_su_whitelist(Oid userId, const char *whitelist)
{
	char	   *rawstring = NULL;
	List	   *elemlist;
	ListCell   *l;
	bool		result = false;

	if (whitelist == NULL || whitelist[0] == '\0')
		return false;

	rawstring = pstrdup(whitelist);

	/* Parse string into list of identifiers */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		/* syntax error in list */
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("invalid syntax in parameter")));
	}

	/* Allow all users to escalate if whitelist is a solo wildcard character. */
	if (list_length(elemlist) == 1)
	{
		char	   *first_elem = NULL;

		first_elem = (char *) linitial(elemlist);
		if (pg_strcasecmp(first_elem, WHITELIST_WILDCARD) == 0)
			return true;
	}

	/*
  	 * Check whole whitelist to see if it contains the current username and no
  	 * wildcard character. Throw an error if the whitelist contains both.
  	 */
	foreach(l, elemlist)
	{
		char	   *elem = (char *) lfirst(l);

		if (pg_strcasecmp(elem, GETUSERNAMEFROMID(userId)) == 0)
			result = true;
		else if (pg_strcasecmp(elem, WHITELIST_WILDCARD) == 0)
				/* No explicit usernames intermingled with wildcard. */
				ereport(ERROR,
						(errcode(ERRCODE_SYNTAX_ERROR),
						 errmsg("invalid syntax in parameter"),
						 errhint("Either remove users from edb_block_commands.su_whitelist "
								 "or remove the wildcard character \"%s\". The whitelist "
								 "cannot contain both.",
								 WHITELIST_WILDCARD)));
	}

	return result;
}

/*
 * Check the query command type and allow/disallow
 * based on GUC settings of the module
 */

static void
edb_check_query(ParseState *pstate, Query *query)
{
	
	/*
	 * Check if commandType is allowed command type 
	 * and according disallow or allow
	 */

	switch(query->commandType)
	{
		case CMD_DELETE:
			if ((disallow_delete || disallow_write) && !(edb_check_su_whitelist(GetUserId(), su_wlist)
									|| edb_check_su_whitelist(GetUserId(), su_delete_wlist)))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 		 errmsg("DELETE statement is not allowed by edb_block_commands configuration")));
			break;

		case CMD_UPDATE:
			if ((disallow_update ||disallow_write) && !(edb_check_su_whitelist(GetUserId(), su_wlist)
                                                                        || edb_check_su_whitelist(GetUserId(), su_update_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 			 errmsg("UPDATE statement is not allowed by edb_block_commands configuration")));
			break;

		case CMD_INSERT:
			if ((disallow_insert || disallow_write) && !(edb_check_su_whitelist(GetUserId(), su_wlist)
                                                                        || edb_check_su_whitelist(GetUserId(), su_insert_wlist))) 
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 			errmsg("INSERT statement is not allowed by edb_block_commands configuration")));
			break;
		
		case CMD_SELECT:
			if ((disallow_select) && !(edb_check_su_whitelist(GetUserId(), su_wlist)
							|| edb_check_su_whitelist(GetUserId(),su_read_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 			errmsg("SELECT statement is not allowed by edb_block_commands configuration")));

		default:
			if ((disallow_write && (query->hasModifyingCTE || query->hasForUpdate)) &&
				!(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(), su_write_wlist)))
                		ereport(ERROR,
                        			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                         			errmsg("Write statement is not allowed by edb_block_commands configuration")));
			break;
	}

	/*
	 * Fallback to normal process, be it the previous hook loaded
	 * or the in-core code path if the previous hook does not exist.
	 */

	if (original_post_parse_analyze_hook != NULL)
		(*original_post_parse_analyze_hook) (pstate, query);
}



#ifdef HAS_PSTMT
/* 10 & up */
static void
edb_block_commands(PlannedStmt *pstmt,
		  const char *queryString,
		  ProcessUtilityContext context,
		  ParamListInfo params,
		  QueryEnvironment *queryEnv,
		  DestReceiver *dest,
		  char *completionTag)
#else
static void
edb_block_commands(Node *parsetree,
		  const char *queryString,
		  ProcessUtilityContext context,
		  ParamListInfo params,
		  DestReceiver *dest,
		  char *completionTag)
#endif
{
#ifdef HAS_PSTMT
	Node	   *parsetree = pstmt->utilityStmt;
#endif
	/*
	 * allow only EDB* Loader command utility command
	 */
	switch (nodeTag(parsetree))
	{
		case T_AlterSystemStmt:
			if ((disallow_alter_system) && !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_alter_system_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("ALTER SYSTEM blocked by edb_block_commands configuration")));
			break;

		case T_EDBLoaderStmt:
                         if ((disallow_edbldr) && !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_edbldr_wlist)))
                         	ereport(ERROR,
                                		(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                                                 errmsg("EDB*loader blocked by edb_block_commands configuration")));
                         break;

		case T_CopyStmt:
			if ((((CopyStmt *) parsetree)->is_program && disallow_copy_program) &&  !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_copy_program_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("COPY PROGRAM blocked by edb_block_commands configuration")));
			else if ((disallow_copy_command) &&  !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_copy_command_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("COPY command blocked by edb_block_commands configuration")));

			break;

		case T_VariableSetStmt:
			if (((strcmp(((VariableSetStmt *) parsetree)->name,
				 "log_statement") == 0) &&
				disallow_log_statement) &&  !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_log_statement_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("\"SET log_statement\" blocked by edb_block_commands configuration")));
			else if ((disallow_set_statement) && (!edb_check_su_whitelist(GetUserId(), su_wlist) || !edb_check_su_whitelist(GetUserId(),su_set_wlist))) 
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("\"SET variables\" blocked by edb_block_commands configuration")));
			break;

		case T_VariableShowStmt:
			if ((disallow_show_command) && !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_show_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						errmsg("\"SHOW variables\" commands are blocked edb_block_commands configuration")));
			break;

		case T_VacuumStmt:
			if ((disallow_vacuum_analyze) &&  !(edb_check_su_whitelist(GetUserId(), su_wlist) || edb_check_su_whitelist(GetUserId(),su_vacuum_analyze_wlist)))
                                ereport(ERROR,
                                                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                                                errmsg("\"VACUUM/ANALYZE\" commands are blocked edb_block_commands configuration")));
                        break;

		default:
			if (!(edb_check_su_whitelist(GetUserId(), su_wlist)))
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						errmsg("Utility commands are blocked edb_block_commands"),
						errhint("Allowed control commands using edb_block_commands are: ALTER SYSTEM/LOAD DATA/SET/VACUUM/ANALYZE/SHOW")));

			break;
	}

	/*
	 * Fallback to normal process, be it the previous hook loaded
	 * or the in-core code path if the previous hook does not exist.
	 */

	if (prev_utility_hook)
#ifdef HAS_PSTMT
		(*prev_utility_hook) (pstmt, queryString, context, params,
				  queryEnv, dest, completionTag);
#else
		(*prev_utility_hook) (parsetree, queryString,
							  context, params,
							  dest, completionTag);
#endif
	 else
#ifdef HAS_PSTMT
		standard_ProcessUtility(pstmt, queryString,
								context, params, queryEnv,
								dest, completionTag);
#else
		 standard_ProcessUtility(parsetree, queryString,
								 context, params,
								 dest, completionTag);
#endif
}

void
_PG_init(void)
{
        
	DefineCustomBoolVariable("edb_block_commands.block_alter_system",
							 "Block ALTER SYSTEM commands",
							 NULL, &disallow_alter_system, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.copy_program",
							 "Blocks COPY PROGRAM commands",
							 NULL, &disallow_copy_program, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.copy_command",
							 "Blocks all COPY commands",
							 NULL, &disallow_copy_command, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.log_statement",
							 "Blocks \"SET log_statement\" commands",
							 NULL, &disallow_log_statement, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.set_statement",
							 "Blocks all \"SET \" commands",
							 NULL, &disallow_set_statement, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.edbldr",
							 "Blocks \"edbldr\" commands",
							 NULL, &disallow_edbldr, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.show",
							 "Blocks \"SHOW\" commands",
							 NULL, &disallow_show_command, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.vacuum_analyze",
							 "Blocks \"VACUUM/ANALYZE\" commands",
							 NULL, &disallow_vacuum_analyze, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.insert",
							 "Blocks \"INSERT\" commands",
							 NULL, &disallow_insert, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.update",
							 "Blocks \"UPDATE\" commands",
							 NULL, &disallow_update, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.delete",
							 "Blocks \"DELETE\" commands",
							 NULL, &disallow_delete, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.write",
							 "Blocks \"WRITE DML\" commands",
							 NULL, &disallow_write, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomBoolVariable("edb_block_commands.read",
							 "Blocks \"SELECT\" commands",
							 NULL, &disallow_select, true, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_whitelist",
							 "Allows a list of users to use edb_block_commands for superuser escalation",
							 NULL, &su_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_alter_system_whitelist",
							 "Allows a list of super users to execute ALTER SYSTEM",
							 NULL, &su_alter_system_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_copy_command_whitelist",
							 "Allows a list of super users to execute COPY command",
							 NULL, &su_copy_command_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_copy_program_whitelist",
							 "Allows a list of super users to execute COPY command",
							 NULL, &su_copy_program_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_log_statement_whitelist",
							 "Allows a list of super users to execute \"SET log_statement\" command",
							 NULL, &su_log_statement_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_show_command_whitelist",
							 "Allows a list of super users to execute SHOW command",
							 NULL, &su_show_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_set_command_whitelist",
							 "Allows a list of super users to execute \"SET variable\" command",
							 NULL, &su_set_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_vacuum_analyze_command_whitelist",
							 "Allows a list of super users to execute \"VACUUM/ANALYZE\" command",
							 NULL, &su_vacuum_analyze_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);


	DefineCustomStringVariable("edb_block_commands.su_edbldr_command_whitelist",
							 "Allows a list of super users to execute edbldr command",
							 NULL, &su_edbldr_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_delete_command_whitelist",
							 "Allows a list of super users to execute DELETE command",
							 NULL, &su_delete_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);


	DefineCustomStringVariable("edb_block_commands.su_insert_command_whitelist",
							 "Allows a list of super users to execute INSERT command",
							 NULL, &su_insert_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_update_command_whitelist",
							 "Allows a list of super users to execute UPDATE command",
							 NULL, &su_update_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_read_whitelist",
							 "Allows a list of super users to execute SELECT command",
							 NULL, &su_read_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("edb_block_commands.su_write_whitelist",
							 "Allows a list of super users to execute DML command",
							 NULL, &su_write_wlist, "", PGC_SIGHUP,
							 0, NULL, NULL, NULL);


	prev_utility_hook = ProcessUtility_hook;
	ProcessUtility_hook = edb_block_commands;
	original_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = edb_check_query;
}

void
_PG_fini(void)
{
    ProcessUtility_hook = prev_utility_hook;
    post_parse_analyze_hook = original_post_parse_analyze_hook;
}
