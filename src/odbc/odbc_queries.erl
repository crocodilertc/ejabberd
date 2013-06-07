%%%----------------------------------------------------------------------
%%% File    : odbc_queries.erl
%%% Author  : Mickael Remond <mremond@process-one.net>
%%% Purpose : ODBC queries dependind on back-end
%%% Created : by Mickael Remond <mremond@process-one.net>
%%%
%%%
%%% ejabberd, Copyright (C) 2002-2013   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%----------------------------------------------------------------------

-module(odbc_queries).
-author("mremond@process-one.net").

-export([get_db_type/0,
         update_t/4,
	 sql_transaction/2,
	 get_last/2,
	 set_last_t/4,
	 del_last/2,
	 get_password/2,
	 set_password_t/3,
	 add_user/3,
	 del_user/2,
	 del_user_return_password/3,
	 list_users/1,
         list_users/2,
	 users_number/1,
         users_number/2,
	 add_spool_sql/2,
	 add_spool/2,
	 get_and_del_spool_msg_t/2,
	 del_spool_msg/2,
	 get_roster/2,
	 get_roster_jid_groups/2,
	 get_roster_groups/3,
	 del_user_roster_t/2,
	 get_roster_by_jid/3,
	 get_rostergroup_by_jid/3,
	 del_roster/3,
	 del_roster_sql/2,
	 update_roster/5,
	 update_roster_sql/4,
	 roster_subscribe/4,
	 get_subscription/3,
	 set_private_data/4,
	 set_private_data_sql/3,
	 get_private_data/3,
	 del_user_private_storage/2,
	 get_default_privacy_list/2,
	 get_default_privacy_list_t/1,
	 get_privacy_list_names/2,
	 get_privacy_list_names_t/1,
	 get_privacy_list_id/3,
	 get_privacy_list_id_t/2,
	 get_privacy_list_data/3,
	 get_privacy_list_data_by_id/2,
         get_privacy_list_data_by_id_t/1,
	 set_default_privacy_list/2,
	 unset_default_privacy_list/2,
	 remove_privacy_list/2,
	 add_privacy_list/2,
	 set_privacy_list/2,
	 del_privacy_lists/3,
	 set_vcard/26,
	 get_vcard/2,
	 escape/1,
	 count_records_where/3,
	 get_roster_version/2,
	 set_roster_version/2]).

%% We have only two compile time options for db queries:
%-define(generic, true).
%-define(mssql, true).
-ifndef(mssql).
-undef(generic).
-define(generic, true).
-endif.

-include("ejabberd.hrl").

%% Almost a copy of string:join/2.
%% We use this version because string:join/2 is relatively
%% new function (introduced in R12B-0).
join([], _Sep) ->
    [];
join([H|T], Sep) ->
    [H, [[Sep, X] || X <- T]].

%% -----------------
%% Generic queries
-ifdef(generic).

get_db_type() ->
    generic.

%% Safe atomic update.
update_t(Table, Fields, Vals, Where) ->
    UPairs = lists:zipwith(fun(A, B) -> A ++ "='" ++ B ++ "'" end,
			   Fields, Vals),
    case ejabberd_odbc:sql_query_t(
	   ["update ", Table, " set ",
	    join(UPairs, ", "),
	    " where ", Where, ";"]) of
	{updated, 1} ->
	    ok;
	_ ->
	    ejabberd_odbc:sql_query_t(
	      ["insert into ", Table, "(", join(Fields, ", "),
	       ") values ('", join(Vals, "', '"), "');"])
    end.

update(LServer, Table, Fields, Vals, Where) ->
    UPairs = lists:zipwith(fun(A, B) -> A ++ "='" ++ B ++ "'" end,
			   Fields, Vals),
    case ejabberd_odbc:sql_query(
	   LServer,
	   ["update ", Table, " set ",
	    join(UPairs, ", "),
	    " where ", Where, ";"]) of
	{updated, 1} ->
	    ok;
	_ ->
	    ejabberd_odbc:sql_query(
	      LServer,
	      ["insert into ", Table, "(", join(Fields, ", "),
	       ") values ('", join(Vals, "', '"), "');"])
    end.

%% F can be either a fun or a list of queries
%% TODO: We should probably move the list of queries transaction
%% wrapper from the ejabberd_odbc module to this one (odbc_queries)
sql_transaction(LServer, F) ->
    ejabberd_odbc:sql_transaction(LServer, F).

get_last(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select seconds, state from last "
       "where username='", Username, "'", " and domain='", LServer, "'"]).

set_last_t(LServer, Username, Seconds, State) ->
    update(LServer, "last", ["username", "seconds", "state"],
	   [Username, Seconds, State],
	   ["username='", Username, "'", " and domain='", LServer, "'"]).

del_last(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from last where username='", Username, "'", " and domain='", LServer, "'"]).

get_password(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select password, ha1 from users "
       "where username='", Username, "'", " and domain='", LServer, "';"]).

set_password_t(LServer, Username, Pass) ->
    PS = ejabberd_config:get_local_option(password_type),
    case PS of
        hashed ->
	        Ha1 = hex:bin_to_hexstr(crypto:md5(Username ++ ":" ++ LServer ++ ":" ++ Pass)),
	        ejabberd_odbc:sql_transaction(
	        LServer,
	        fun() ->
		        update_t("users", ["username", "ha1"],
			       [Username, Ha1],
			       ["username='", Username ,"'", " and domain='", LServer, "'"])
	        end);
        _ ->
	    ejabberd_odbc:sql_transaction(
	        LServer,
	        fun() ->
		        update_t("users", ["username", "password"],
			       [Username, Pass],
			       ["username='", Username ,"'", " and domain='", LServer, "'"])
	        end)
    end.

add_user(LServer, Username, Pass) ->
    PS = ejabberd_config:get_local_option(password_type),
    case PS of
        hashed ->
            Ha1 = hex:bin_to_hexstr(crypto:md5(Username ++ ":" ++ LServer ++ ":" ++ Pass)),
                ejabberd_odbc:sql_query(
    	            LServer,
	                ["insert into users(username, ha1, domain) "
	                "values ('", Username, "', '", Ha1, "', '", LServer, "');"]);
        _ ->
            ejabberd_odbc:sql_query(
    	        LServer,
	            ["insert into users(username, password, domain) "
	            "values ('", Username, "', '", Pass, "', '", LServer, "');"])
    end.

del_user(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from users where username='", Username, "'", " and domain='", LServer, "';"]).

del_user_return_password(_LServer, Username, Pass) ->
    PS = ejabberd_config:get_local_option(password_type),
    P = case PS of
        hashed ->
            Ha1 = hex:bin_to_hexstr(crypto:md5(Username ++ ":" ++ _LServer ++ ":" ++ Pass)),
            ejabberd_odbc:sql_query_t(
	            ["select ha1 from users where username='",
	            Username, "'", " and domain='", _LServer, "';"]),
            ejabberd_odbc:sql_query_t(["delete from users "
		        "where username='", Username,
			    "' and ha1='", Ha1, "'", " and domain='", _LServer, "';"]);
        _ ->
            ejabberd_odbc:sql_query_t(
	            ["select password from users where username='",
	            Username, "'", " and domain='", _LServer, "';"]),
            ejabberd_odbc:sql_query_t(["delete from users "
		        "where username='", Username,
			    "' and password='", Pass, "'", " and domain='", _LServer, "';"])
        end,
    P.

list_users(LServer) ->
    ejabberd_odbc:sql_query(
      LServer,
      "select username from users where domain='", LServer, "';").

list_users(LServer, [{from, Start}, {to, End}]) when is_integer(Start) and
                                                     is_integer(End) ->
    list_users(LServer, [{limit, End-Start+1}, {offset, Start-1}]);
list_users(LServer, [{prefix, Prefix}, {from, Start}, {to, End}]) when is_list(Prefix) and
                                                                       is_integer(Start) and
                                                                       is_integer(End) ->
    list_users(LServer, [{prefix, Prefix}, {limit, End-Start+1}, {offset, Start-1}]);

list_users(LServer, [{limit, Limit}, {offset, Offset}]) when is_integer(Limit) and
                                                             is_integer(Offset) ->
    ejabberd_odbc:sql_query(
      LServer,
      io_lib:format(
        "select username from users where domain='~s' " ++
        "order by username " ++
        "limit ~w offset ~w", [LServer, Limit, Offset]));
list_users(LServer, [{prefix, Prefix},
                     {limit, Limit},
                     {offset, Offset}]) when is_list(Prefix) and
                                             is_integer(Limit) and
                                             is_integer(Offset) ->
    ejabberd_odbc:sql_query(
      LServer,
      io_lib:format("select username from users " ++
                    "where username like '~s%' and domain='~s' " ++
                    "order by username " ++
                    "limit ~w offset ~w ", [LServer,Prefix, Limit, Offset])).

users_number(LServer) ->
    case element(1, ejabberd_config:get_local_option({odbc_server, LServer})) of
    pgsql ->
	case ejabberd_config:get_local_option({pgsql_users_number_estimate, LServer}) of
	true ->
	    ejabberd_odbc:sql_query(
	    LServer,
	    "select reltuples from pg_class where oid = 'users'::regclass::oid");
	_ ->
	    ejabberd_odbc:sql_query(
	    LServer,
	    "select count(*) from users where domain='", LServer, "'")
        end;
    _ ->
	ejabberd_odbc:sql_query(
	LServer,
	"select count(*) from users where domain='", LServer, "'")
    end.

users_number(LServer, [{prefix, Prefix}]) when is_list(Prefix) ->
    ejabberd_odbc:sql_query(
      LServer,
      io_lib:fwrite("select count(*) from users " ++
                    %% Warning: Escape prefix at higher level to prevent SQL
                    %%          injection.
                    "where username like '~s%' and domain='~s'", [Prefix,LServer]));
users_number(LServer, []) ->
    users_number(LServer).

%% KIRA Q about Domain!!!
add_spool_sql(Username, XML) ->
    ["insert into spool(username, xml) "
     "values ('", Username, "', '",
     XML,
     "');"].

add_spool(LServer, Queries) ->
    ejabberd_odbc:sql_transaction(
      LServer, Queries).

get_and_del_spool_msg_t(LServer, Username) ->
    F = fun() ->
		Result = ejabberd_odbc:sql_query_t(
			   ["select username, xml from spool where username='", Username, "'", " and domain='", LServer, "'"
			    "  order by seq;"]),
		ejabberd_odbc:sql_query_t(
		  ["delete from spool where username='", Username, "'", " and domain='", LServer, "';"]),
		Result
	end,
    ejabberd_odbc:sql_transaction(LServer,F).

del_spool_msg(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from spool where username='", Username, "'", " and domain='", LServer, "';"]).

get_roster(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select username, jid, nick, subscription, ask, "
       "askmessage, server, subscribe, type from rosterusers "
       "where username='", Username, "'", " and domain='", LServer, "'"]).

get_roster_jid_groups(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select jid, grp from rostergroups "
       "where username='", Username, "'", " and domain='", LServer, "'"]).

get_roster_groups(_LServer, Username, SJID) ->
    ejabberd_odbc:sql_query_t(
      ["select grp from rostergroups "
       "where username='", Username, "' ", " and domain='", _LServer, "' "
       "and jid='", SJID, "';"]).

del_user_roster_t(LServer, Username) ->
    ejabberd_odbc:sql_transaction(
      LServer,
      fun() ->
	      ejabberd_odbc:sql_query_t(
		["delete from rosterusers "
		 "      where username='", Username, "'", " and domain='", LServer, "';"]),
	      ejabberd_odbc:sql_query_t(
		["delete from rostergroups "
		 "      where username='", Username, "'", " and domain='", LServer, "';"])
      end).

get_roster_by_jid(_LServer, Username, SJID) ->
    ejabberd_odbc:sql_query_t(
    ["select username, jid, nick, subscription, "
     "ask, askmessage, server, subscribe, type from rosterusers "
     "where username='", Username, "' ", " and domain='", _LServer, "' ",
     "and jid='", SJID, "';"]).

get_rostergroup_by_jid(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select grp from rostergroups "
       "where username='", Username, "' ", " and domain='", LServer, "' ",
       "and jid='", SJID, "'"]).

del_roster(_LServer, Username, SJID) ->
    ejabberd_odbc:sql_query_t(
      ["delete from rosterusers "
       "      where username='", Username, "' ", " and domain='", _LServer, "' ",
       "        and jid='", SJID, "';"]),
    ejabberd_odbc:sql_query_t(
      ["delete from rostergroups "
       "      where username='", Username, "' ", " and domain='", _LServer, "' ",
       "        and jid='", SJID, "';"]).

%% KIRA Q about Domain!!!
del_roster_sql(Username, SJID) ->
    [["delete from rosterusers "
      "      where username='", Username, "' "
      "        and jid='", SJID, "';"],
     ["delete from rostergroups "
      "      where username='", Username, "' "
      "        and jid='", SJID, "';"]].

update_roster(_LServer, Username, SJID, ItemVals, ItemGroups) ->
    ?DEBUG("Xuyaru update_roster",[]),
    update_t("rosterusers",
	     ["username", "jid", "nick", "subscription", "ask",
	      "askmessage", "server", "subscribe", "type", "domain"],
	     ItemVals ++ _LServer,
	     ["username='", Username, "' and domain='", _LServer, "' and jid='", SJID, "'"]),
    ?DEBUG("Poxuyaril update_roster",[]),
    ejabberd_odbc:sql_query_t(
      ["delete from rostergroups "
       "      where username='", Username, "' and domain='", _LServer, "' ",
       "        and jid='", SJID, "';"]),
    lists:foreach(fun(ItemGroup) ->
			  ejabberd_odbc:sql_query_t(
			    ["insert into rostergroups("
			     "              username, jid, grp, domain) "
			     " values ('", join(ItemGroup, "', '"), "', '", _LServer, "');"])
		  end,
		  ItemGroups).

%% KIRA Q about Domain!!!
update_roster_sql(Username, SJID, ItemVals, ItemGroups) ->
    [["delete from rosterusers "
      "      where username='", Username, "' "
      "        and jid='", SJID, "';"],
     ["insert into rosterusers("
      "              username, jid, nick, "
      "              subscription, ask, askmessage, "
      "              server, subscribe, type) "
      " values ('", join(ItemVals, "', '"), "');"],
     ["delete from rostergroups "
      "      where username='", Username, "' "
      "        and jid='", SJID, "';"]] ++
     [["insert into rostergroups("
       "              username, jid, grp) "
       " values ('", join(ItemGroup, "', '"), "');"] ||
	 ItemGroup <- ItemGroups].

roster_subscribe(_LServer, Username, SJID, ItemVals) ->
    update_t("rosterusers",
	     ["username", "jid", "nick", "subscription", "ask",
	      "askmessage", "server", "subscribe", "type"],
	     ItemVals,
	     ["username='", Username, "' and jid='", SJID, "'", " and domain='", _LServer, "'"]).

get_subscription(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select subscription from rosterusers "
       "where username='", Username, "' "
       "and jid='", SJID, "'", " and domain='", LServer, "'"]).

set_private_data(_LServer, Username, LXMLNS, SData) ->
    update_t("private_storage",
	     ["username", "namespace", "data", "domain"],
	     [Username, LXMLNS, SData, _LServer], 
	     ["username='", Username, "' and namespace='", LXMLNS, "'", " and domain='", _LServer, "'"]).

set_private_data_sql(Username, LXMLNS, SData) ->
    [["delete from private_storage "
       "where username='", Username, "' and "
       "namespace='", LXMLNS, "';"],
      ["insert into private_storage(username, namespace, data) "
       "values ('", Username, "', '", LXMLNS, "', "
       "'", SData, "');"]].

get_private_data(LServer, Username, LXMLNS) ->
    ejabberd_odbc:sql_query(
		 LServer,
		 ["select data from private_storage "
		  "where username='", Username, "' and "
		  "namespace='", LXMLNS, "'", " and domain='", LServer, "';"]).

del_user_private_storage(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from private_storage where username='", Username, "'", " and domain='", LServer, "';"]).

set_vcard(LServer, LUsername, SBDay, SCTRY, SEMail, SFN, SFamily, SGiven,
	  SLBDay, SLCTRY, SLEMail, SLFN, SLFamily, SLGiven, SLLocality,
	  SLMiddle, SLNickname, SLOrgName, SLOrgUnit, SLocality, SMiddle,
	  SNickname, SOrgName, SOrgUnit, SVCARD, Username) ->
    ejabberd_odbc:sql_transaction(
      LServer,
      fun() ->
	      update_t("vcard", ["username", "vcard"],
		       [LUsername, SVCARD],
		       ["username='", LUsername, "'"]),
	      update_t("vcard_search",
		       ["username", "lusername", "fn", "lfn", "family",
			"lfamily", "given", "lgiven", "middle", "lmiddle",
			"nickname", "lnickname", "bday", "lbday", "ctry",
			"lctry", "locality", "llocality", "email", "lemail",
			"orgname", "lorgname", "orgunit", "lorgunit", "domain"],
		       [Username, LUsername, SFN, SLFN, SFamily, SLFamily,
			SGiven, SLGiven, SMiddle, SLMiddle, SNickname,
			SLNickname, SBDay, SLBDay, SCTRY, SLCTRY,
			SLocality, SLLocality, SEMail, SLEMail, SOrgName,
			SLOrgName, SOrgUnit, SLOrgUnit, LServer],
		       ["lusername='", LUsername, "'", " and domain='", LServer, "'"])
      end).

get_vcard(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select vcard from vcard "
       "where username='", Username, "'", " and domain='", LServer, "';"]).

get_default_privacy_list(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select name from privacy_default_list "
       "where username='", Username, "'", " and domain='", LServer, "';"]).

%% KIRA Q Domain?
get_default_privacy_list_t(Username) ->
    ejabberd_odbc:sql_query_t(
      ["select name from privacy_default_list "
       "where username='", Username, "';"]).

get_privacy_list_names(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select name from privacy_list "
       "where username='", Username, "'", " and domain='", LServer, "';"]).

%% KIRA Q Domain?
get_privacy_list_names_t(Username) ->
    ejabberd_odbc:sql_query_t(
      ["select name from privacy_list "
       "where username='", Username, "';"]).

get_privacy_list_id(LServer, Username, SName) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select id from privacy_list "
       "where username='", Username, "' and name='", SName, "'", " and domain='", LServer, "';"]).

%% KIRA Q Domain?
get_privacy_list_id_t(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["select id from privacy_list "
       "where username='", Username, "' and name='", SName, "';"]).

get_privacy_list_data(LServer, Username, SName) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select t, value, action, ord, match_all, match_iq, "
       "match_message, match_presence_in, match_presence_out "
       "from privacy_list_data "
       "where id = (select id from privacy_list where "
       "            username='", Username, "' and name='", SName, "' and domain='", LServer, "') "
       "order by ord;"]).

get_privacy_list_data_by_id(LServer, ID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select t, value, action, ord, match_all, match_iq, "
       "match_message, match_presence_in, match_presence_out "
       "from privacy_list_data "
       "where id='", ID, "' and domain='", LServer, "' order by ord;"]).

%% KIRA Q Domain?
get_privacy_list_data_by_id_t(ID) ->
    ejabberd_odbc:sql_query_t(
      ["select t, value, action, ord, match_all, match_iq, "
       "match_message, match_presence_in, match_presence_out "
       "from privacy_list_data "
       "where id='", ID, "' order by ord;"]).

%% KIRA Q Domain?
set_default_privacy_list(Username, SName) ->
    update_t("privacy_default_list", ["username", "name"],
	     [Username, SName], ["username='", Username, "'"]).

unset_default_privacy_list(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from privacy_default_list "
       "      where username='", Username, "'", " and domain='", LServer, "';"]).

%% KIRA Q Domain?
remove_privacy_list(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["delete from privacy_list "
       "where username='", Username, "' and name='", SName, "';"]).

%% KIRA Q Domain?
add_privacy_list(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["insert into privacy_list(username, name) "
       "values ('", Username, "', '", SName, "');"]).

%% KIRA Q Domain?
set_privacy_list(ID, RItems) ->
    ejabberd_odbc:sql_query_t(
      ["delete from privacy_list_data "
       "where id='", ID, "';"]),
    lists:foreach(fun(Items) ->
			  ejabberd_odbc:sql_query_t(
			    ["insert into privacy_list_data("
			     "id, t, value, action, ord, match_all, match_iq, "
			     "match_message, match_presence_in, "
			     "match_presence_out "
			     ") "
			     "values ('", ID, "', '",
			     join(Items, "', '"), "');"])
		  end, RItems).

del_privacy_lists(LServer, Server, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from privacy_list where username='", Username, "'", " and domain='", LServer, "';"]),
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from privacy_list_data where value='", Username++"@"++Server, "'", " and domain='", LServer, "';"]),
    ejabberd_odbc:sql_query(
      LServer,
      ["delete from privacy_default_list where username='", Username, "'", " and domain='", LServer, "';"]).

%% Characters to escape
escape($\0) -> "\\0";
escape($\n) -> "\\n";
escape($\t) -> "\\t";
escape($\b) -> "\\b";
escape($\r) -> "\\r";
escape($')  -> "''";
escape($")  -> "\\\"";
escape($\\) -> "\\\\";
escape(C)   -> C.

%% Count number of records in a table given a where clause
count_records_where(LServer, Table, WhereClause) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select count(*) from ", Table, " ", WhereClause, ";"]).


get_roster_version(LServer, LUser) ->
	ejabberd_odbc:sql_query(LServer,
		["select version from roster_version where username = '", LUser, "'", " and domain='", LServer, "'"]).
set_roster_version(LUser, Version) ->
	update_t("roster_version", ["username", "version", "domain"], [LUser, Version], ["username = '", LUser, "'"]).
-endif.

%% -----------------
%% MSSQL queries
-ifdef(mssql).

get_db_type() ->
    mssql.

%% Queries can be either a fun or a list of queries
sql_transaction(LServer, Queries) when is_list(Queries) ->
    %% SQL transaction based on a list of queries
    %% This function automatically
    F = fun() ->
    	lists:foreach(fun(Query) ->
    		ejabberd_odbc:sql_query(LServer, Query)
    	end, Queries)
      end,
    {atomic, catch F()};
sql_transaction(_LServer, FQueries) ->
    {atomic, catch FQueries()}.

get_last(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_last '", Username, "'", LServer, "'"]).

set_last_t(LServer, Username, Seconds, State) ->
    Result = ejabberd_odbc:sql_query(
		 LServer,
		 ["EXECUTE dbo.set_last '", Username, "', '", Seconds,
		  "', '", State, "'", LServer, "'"]),
    {atomic, Result}.

del_last(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.del_last '", Username, "'", LServer, "'"]).

get_password(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_password '", Username, "'", LServer, "'"]).

set_password_t(LServer, Username, Pass) ->
    Result = ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.set_password '", Username, "', '", Pass, "'", LServer, "'"]),
    {atomic, Result}.

add_user(LServer, Username, Pass) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.add_user '", Username, "', '", Pass, "'", LServer, "'"]).

del_user(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.del_user '", Username ,"'", LServer, "'"]).

del_user_return_password(LServer, Username, Pass) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.del_user_return_password '", Username, "'", LServer, "'"]),
    Pass.

list_users(LServer) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.list_users", LServer, "'").

list_users(LServer, _) ->
    % scope listing not supported
    list_users(LServer).

users_number(LServer) ->
	ejabberd_odbc:sql_query(
	      LServer,
	      "select count(*) from users with (nolock)", LServer, "'").

users_number(LServer, _) ->
    % scope listing not supported
    users_number(LServer).

add_spool_sql(Username, XML) ->
    ["EXECUTE dbo.add_spool '", Username, "' , '",XML,"'"].

add_spool(LServer, Queries) ->
    lists:foreach(fun(Query) ->
			  ejabberd_odbc:sql_query(LServer, Query)
		  end,
		  Queries).

get_and_del_spool_msg_t(LServer, Username) ->
    [Result] = case ejabberd_odbc:sql_query(
		    LServer,
		    ["EXECUTE dbo.get_and_del_spool_msg '", Username, "'", LServer, "'"]) of
		   Rs when is_list(Rs) ->
		     lists:filter(fun({selected, _Header, _Row}) ->
					  true;
				     ({updated, _N}) ->
					  false
				  end,
				  Rs);
		   Rs -> [Rs]
	       end,
    {atomic, Result}.

del_spool_msg(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.del_spool_msg '", Username, "'", LServer, "'"]).

get_roster(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_roster '", Username, "'", LServer, "'"]).

get_roster_jid_groups(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_roster_jid_groups '", Username, "'", LServer, "'"]).

get_roster_groups(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_roster_groups '", Username, "' , '", SJID, "'", LServer, "'"]).

del_user_roster_t(LServer, Username) ->
    Result = ejabberd_odbc:sql_query(
		      LServer,
		      ["EXECUTE dbo.del_user_roster '", Username, "'", LServer, "'"]),
    {atomic, Result}.

get_roster_by_jid(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_roster_by_jid '", Username, "' , '", SJID, "'", LServer, "'"]).

get_rostergroup_by_jid(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_rostergroup_by_jid '", Username, "' , '", SJID, "'", LServer, "'"]).

del_roster(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.del_roster '", Username, "', '", SJID, "', '", LServer, "'"]).

del_roster_sql(Username, SJID) ->
    ["EXECUTE dbo.del_roster '", Username, "', '", SJID, "'"].

update_roster(LServer, Username, SJID, ItemVals, ItemGroups) ->
    Query1 = ["EXECUTE dbo.del_roster '", Username, "', '", SJID, "', '", LServer, "'"],
    ejabberd_odbc:sql_query(LServer, lists:flatten(Query1)),
    Query2 = ["EXECUTE dbo.add_roster_user ", ItemVals, "', '", LServer, "'"],
    ejabberd_odbc:sql_query(LServer, lists:flatten(Query2)),
    Query3 = ["EXECUTE dbo.del_roster_groups '", Username, "', '", SJID, "', '", LServer, "'"],
    ejabberd_odbc:sql_query(LServer, lists:flatten(Query3)),
    lists:foreach(fun(ItemGroup) ->
			  Query = ["EXECUTE dbo.add_roster_group ",
				   ItemGroup, "', '", LServer, "'"],
			  ejabberd_odbc:sql_query(LServer,
						  lists:flatten(Query))
		  end,
		  ItemGroups).

update_roster_sql(Username, SJID, ItemVals, ItemGroups) ->
    ["BEGIN TRANSACTION ",
     "EXECUTE dbo.del_roster_groups '", Username, "','", SJID, "' ",
     "EXECUTE dbo.add_roster_user ", ItemVals, " "] ++
	[lists:flatten("EXECUTE dbo.add_roster_group ", ItemGroup, " ")
	 || ItemGroup <- ItemGroups] ++
	["COMMIT"].

roster_subscribe(LServer, _Username, _SJID, ItemVals) ->
    catch ejabberd_odbc:sql_query(
	    LServer,
	    ["EXECUTE dbo.add_roster_user ", ItemVals, "','", LServer, "'"]).

get_subscription(LServer, Username, SJID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_subscription '", Username, "' , '", SJID, "', ", LServer, "'"]).

set_private_data(LServer, Username, LXMLNS, SData) ->
    ejabberd_odbc:sql_query(
	    LServer,
	    set_private_data_sql(Username, LXMLNS, SData)).

set_private_data_sql(Username, LXMLNS, SData) ->
    ["EXECUTE dbo.set_private_data '", Username, "' , '", LXMLNS, "' , '", SData, "'"].

get_private_data(LServer, Username, LXMLNS) ->
    ejabberd_odbc:sql_query(
        LServer,
        ["EXECUTE dbo.get_private_data '", Username, "' , '", LXMLNS, "' , '", LServer, "'"]).

del_user_private_storage(LServer, Username) ->
    ejabberd_odbc:sql_query(
        LServer,
        ["EXECUTE dbo.del_user_storage '", Username, "', '", LServer, "'"]).

set_vcard(LServer, LUsername, SBDay, SCTRY, SEMail, SFN, SFamily, SGiven,
	  SLBDay, SLCTRY, SLEMail, SLFN, SLFamily, SLGiven, SLLocality,
	  SLMiddle, SLNickname, SLOrgName, SLOrgUnit, SLocality, SMiddle,
	  SNickname, SOrgName, SOrgUnit, SVCARD, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.set_vcard '", SVCARD, "' , '", Username, "' , '", LUsername, "' , '",
       SFN, "' , '", SLFN, "' , '", SFamily, "' , '", SLFamily, "' , '",
       SGiven, "' , '", SLGiven, "' , '", SMiddle, "' , '", SLMiddle, "' , '",
       SNickname, "' , '", SLNickname, "' , '", SBDay, "' , '", SLBDay, "' , '",
       SCTRY, "' , '", SLCTRY, "' , '", SLocality, "' , '", SLLocality, "' , '",
       SEMail, "' , '", SLEMail, "' , '", SOrgName, "' , '", SLOrgName, "' , '",
       SOrgUnit, "' , '", SLOrgUnit, "', ", LServer, "'"]).

get_vcard(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_vcard '", Username, "', ", LServer, "'"]).

get_default_privacy_list(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_default_privacy_list '", Username, "', ", LServer, "'"]).

get_default_privacy_list_t(Username) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.get_default_privacy_list '", Username, "'"]).

get_privacy_list_names(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_privacy_list_names '", Username, "', '" , LServer, "'"]).

get_privacy_list_names_t(Username) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.get_privacy_list_names '", Username, "'"]).

get_privacy_list_id(LServer, Username, SName) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_privacy_list_id '", Username, "' , '", SName, "', '", LServer, "'"]).

get_privacy_list_id_t(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.get_privacy_list_id '", Username, "' , '", SName, "'"]).

get_privacy_list_data(LServer, Username, SName) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_privacy_list_data '", Username, "' , '", SName, "', ", LServer, "'"]).

get_privacy_list_data_by_id(LServer, ID) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_privacy_list_data_by_id '", ID, "', '", LServer, "'"]).

get_privacy_list_data_by_id_t(ID) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.get_privacy_list_data_by_id '", ID, "'"]).

set_default_privacy_list(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.set_default_privacy_list '", Username, "' , '", SName, "'"]).

unset_default_privacy_list(LServer, Username) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.unset_default_privacy_list '", Username, "', '", LServer, "'"]).

remove_privacy_list(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.remove_privacy_list '", Username, "' , '", SName, "'"]).

add_privacy_list(Username, SName) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.add_privacy_list '", Username, "' , '", SName, "'"]).

set_privacy_list(ID, RItems) ->
    ejabberd_odbc:sql_query_t(
      ["EXECUTE dbo.del_privacy_list_by_id '", ID, "'"]),

    lists:foreach(fun(Items) ->
			  ejabberd_odbc:sql_query_t(
				["EXECUTE dbo.set_privacy_list '", ID, "', '", join(Items, "', '"), "'"])
		  end, RItems).

del_privacy_lists(LServer, Server, Username) ->
	ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.del_privacy_lists @Server='", Server ,"' @username='", Username, "' @domain='", LServer, "'"]).

%% Characters to escape
escape($\0) -> "\\0";
escape($\t) -> "\\t";
escape($\b) -> "\\b";
escape($\r) -> "\\r";
escape($')  -> "\''";
escape($")  -> "\\\"";
escape(C)   -> C.

%% Count number of records in a table given a where clause
%% KIRA Q Domain should be from WHereClause ... ?
count_records_where(LServer, Table, WhereClause) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["select count(*) from ", Table, " with (nolock) ", WhereClause]).

get_roster_version(LServer, LUser) ->
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.get_roster_version '", LUser, "', '", LServer, "'"]).

set_roster_version(Username, Version) ->
    %% This function doesn't know the vhost, so we hope it's the first one defined:
    LServer = ?MYNAME,
    ejabberd_odbc:sql_query(
      LServer,
      ["EXECUTE dbo.set_roster_version '", Username, "', '", Version, "'"]).
-endif.
