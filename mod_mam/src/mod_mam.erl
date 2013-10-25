-module(mod_mam).
-behavior(gen_mod).
-export([start/2, stop/1]).
%% ejabberd handlers
-export([process_mam_iq/3,
         on_send_packet/3,
         on_receive_packet/4,
         on_remove_user/2]).
-include("ejabberd.hrl").
-include("jlib.hrl").
-include("exmpp_xml.hrl").


%% ----------------------------------------------------------------------
%% Datetime types
-type iso8601_datetime_list() :: list().
%% Milliseconds from 01.01.1970
-type milliseconds_timestamp() :: non_neg_integer().

%% ----------------------------------------------------------------------
%% XMPP types
-type server_hostname() :: list().
-type literal_username() :: list().
-type escaped_username() :: list().
-type escaped_jid() :: list().
-type literal_jid() :: list().
-type escaped_resource() :: list().
-type elem() :: #xmlelement{}.
-type jid() :: tuple().


%% ----------------------------------------------------------------------
%% Other types
-type filter() :: iolist().
-type escaped_message_id() :: list().
-type archive_behaviour() :: list(). % "roster" | "always" | "never".

%% ----------------------------------------------------------------------
%% Constants

-define(NS_MAM, "urn:xmpp:mam:tmp").

default_result_limit() -> 50.

max_result_limit() -> 50.

encode_direction(incoming) -> "I";
encode_direction(outgoing) -> "O".

encode_behaviour("roster") -> "R";
encode_behaviour("always") -> "A";
encode_behaviour("never")  -> "N".

decode_behaviour("R") -> "roster";
decode_behaviour("A") -> "always";
decode_behaviour("N") -> "never".

%% ----------------------------------------------------------------------
%% gen_mod callbacks

start(Host, Opts) ->
    ?INFO_MSG("mod_mam starting", []),
    IQDisc = gen_mod:get_opt(iqdisc, Opts, one_queue), %% Type
    mod_disco:register_feature(Host, ?NS_MAM),
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, ?NS_MAM, ?MODULE, process_mam_iq, IQDisc),
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE, on_send_packet, 90),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, on_receive_packet, 90),
    ejabberd_hooks:add(remove_user, Host, ?MODULE, on_remove_user, 50),
    ok.

stop(Host) ->
    ?INFO_MSG("mod_mam stopping", []),
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_MAM),
    ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, on_send_packet, 90),
    ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, on_receive_packet, 90),
    ejabberd_hooks:delete(remove_user, Host, ?MODULE, on_remove_user, 50),
    ok.

%% ----------------------------------------------------------------------
%% hooks and handlers

%% `To' is an account or server entity hosting the archive.
%% Servers that archive messages on behalf of local users SHOULD expose archives 
%% to the user on their bare JID (i.e. `From.luser'),
%% while a MUC service might allow MAM queries to be sent to the room's bare JID
%% (i.e `To.luser').
process_mam_iq(From=#jid{luser = LUser, lserver = LServer},
               _To,
               IQ=#iq{type = set,
                      sub_el = PrefsEl = #xmlelement{name = "prefs"}}) ->
    ?DEBUG("Handling mam prefs IQ~n    from ~p ~n    packet ~p.",
              [From, IQ]),
    {DefaultMode, AlwaysJIDs, NeverJIDs} = parse_prefs(PrefsEl),
    ?DEBUG("Parsed data~n\tDefaultMode ~p~n\tAlwaysJIDs ~p~n\tNeverJIDS ~p~n",
              [DefaultMode, AlwaysJIDs, NeverJIDs]),
    update_settings(LServer, LUser, DefaultMode, AlwaysJIDs, NeverJIDs),
    ResultPrefsEl = result_prefs(DefaultMode, AlwaysJIDs, NeverJIDs),
    IQ#iq{type = result, sub_el = [ResultPrefsEl]};

process_mam_iq(From=#jid{luser = LUser, lserver = LServer},
               _To,
               IQ=#iq{type = get,
                      sub_el = #xmlelement{name = "prefs"}}) ->
    ?DEBUG("Handling mam prefs IQ~n    from ~p ~n    packet ~p.",
              [From, IQ]),
    {DefaultMode, AlwaysJIDs, NeverJIDs} = get_prefs(LServer, LUser, "always"),
    ?DEBUG("Extracted data~n\tDefaultMode ~p~n\tAlwaysJIDs ~p~n\tNeverJIDS ~p~n",
              [DefaultMode, AlwaysJIDs, NeverJIDs]),
    ResultPrefsEl = result_prefs(DefaultMode, AlwaysJIDs, NeverJIDs),
    IQ#iq{type = result, sub_el = [ResultPrefsEl]};

process_mam_iq(From=#jid{lserver = LServer},    
%%process_mam_iq(From=#jid{luser = LUser, lserver = LServer},
               To,
               IQ=#iq{type = get,
                      sub_el = QueryEl = #xmlelement{name = "query"}}) ->
    ?DEBUG("Handling mam IQ~n    from ~p ~n    to ~p~n    packet ~p.",
              [From, To, IQ]),
    QueryID = xml:get_tag_attr_s("queryid", QueryEl),
    %% Filtering by date.
    %% Start :: integer() | undefined
    Start = maybe_milliseconds_timestamp(xml:get_path_s(QueryEl, [{elem, "start"}, cdata])),
    End   = maybe_milliseconds_timestamp(xml:get_path_s(QueryEl, [{elem, "end"}, cdata])),
    RSM   = jlib:rsm_decode(QueryEl),
    %% #rsm_in{
    %%    max = non_neg_integer() | undefined,
    %%    direction = before | aft | undefined,
    %%    %% id is empty, if cdata does not exists.
    %%    id = list() | undefined,
    %%    index = non_neg_integer() | undefined}
    %% Filtering by contact.
    With  = xml:get_path_s(QueryEl, [{elem, "with"}, cdata]),
    {WithSJID, WithSResource} =
    case With of
        "" -> {undefined, undefined};
        _    ->
            WithJID = #jid{lresource = WithLResource} = jlib:string_to_jid(With),
            WithBareJID = jlib:jid_remove_resource(WithJID),
            {ejabberd_odbc:escape(jlib:jid_to_string(WithBareJID)),
             case WithLResource of "" -> undefined;
                  _ -> ejabberd_odbc:escape(WithLResource) end}
    end,
    %% This element's name is "limit".
    %% But it must be "max" according XEP-0313.
    PageSize = min(max_result_limit(),
                   maybe_integer(get_one_of_path_bin(QueryEl, [
                    [{elem, "set"}, {elem, "max"}, cdata],
                    [{elem, "set"}, {elem, "limit"}, cdata]
                   ]), default_result_limit())),


    ?DEBUG("Parsed data~n\tStart ~p~n\tEnd ~p~n\tQueryId ~p~n\tPageSize ~p~n"
              "\tWithSJID ~p~n\tWithSResource ~p~n\tRSM: ~p~n",
              [Start, End, QueryID, PageSize, WithSJID, WithSResource, RSM]),
    SUser = ejabberd_odbc:escape(jlib:jid_to_string(jlib:jid_remove_resource(From))),
%%    SUser = ejabberd_odbc:escape(LUser),
    Filter = prepare_filter(SUser, Start, End, WithSJID, WithSResource),
    TotalCount = calc_count(LServer, Filter),
    Offset     = calc_offset(LServer, Filter, PageSize, TotalCount, RSM),
    ?DEBUG("RSM info: ~nTotal count: ~p~nOffset: ~p~n",
              [TotalCount, Offset]),
    MessageRows = extract_messages(LServer, Filter, Offset, PageSize),
    {FirstId, LastId} =
        case MessageRows of
            []    -> {undefined, undefined};
            [_|_] -> {message_row_to_id(hd(MessageRows)),
                      message_row_to_id(lists:last(MessageRows))}
        end,
    [send_message(To, From, message_row_to_xml(M, QueryID))
     || M <- MessageRows],
    ResultSetEl = result_set(FirstId, LastId, Offset, TotalCount),
    ResultQueryEl = result_query(ResultSetEl),
    %% On receiving the query, the server pushes to the client a series of
    %% messages from the archive that match the client's given criteria,
    %% and finally returns the <iq/> result.
    IQ#iq{type = result, sub_el = [ResultQueryEl]}.


%% @doc Handle an outgoing message.
%%
%% Note: for outgoing messages, the server MUST use the value of the 'to' 
%%       attribute as the target JID. 
on_send_packet(From, To, Packet) ->

    ?DEBUG("Send packet~n    from ~p ~n    to ~p~n    packet ~p.",
              [From, To, Packet]),
    handle_packet(outgoing, From, To, From, Packet).

%% @doc Handle an incoming message.
%%
%% Note: For incoming messages, the server MUST use the value of the
%%       'from' attribute as the target JID. 
on_receive_packet(_JID, From, To, Packet) ->
    ?DEBUG("Receive packet~n    from ~p ~n    to ~p~n    packet ~p.",
              [From, To, Packet]),
    handle_packet(incoming, To, From, From, Packet),
    ok.

on_remove_user(User, Server) ->
    LUser = jlib:nodeprep(User),
    LServer = jlib:nameprep(Server),
    SUser = ejabberd_odbc:escape(LUser),
    remove_user(LServer, SUser),
    ?INFO_MSG("Remove user ~p from ~p.", [LUser, LServer]),
    ok.

%% ----------------------------------------------------------------------
%% Helpers

handle_packet(Dir,
               _LocalJID=#jid{luser = LUser, lserver = LServer},
               RemoteJID=#jid{lresource = RLResource},
               FromJID=#jid{}, Packet) ->
    IsComplete = is_complete_message(Packet),
    ?DEBUG("IsComplete ~p.", [IsComplete]),
    case IsComplete of
        true ->
            SUser = ejabberd_odbc:escape(LUser),
            BareSLJID = ejabberd_odbc:escape(jlib:jid_to_string(jlib:jid_remove_resource(_LocalJID))),
            %% Convert `#jid{}' to prepared `{S,U,R}'
            LRJID = jlib:jid_tolower(RemoteJID),
            BareLRJID = jlib:jid_remove_resource(LRJID),
            SRJID = ejabberd_odbc:escape(jlib:jid_to_string(LRJID)),
            BareSRJID = ejabberd_odbc:escape(jlib:jid_to_string(BareLRJID)),
            IsInteresting =
            case behaviour(LServer, SUser, SRJID, BareSRJID) of
                always -> true;
                never  -> false;
                roster -> is_jid_in_user_roster(LServer, LUser, BareSRJID)
            end,
            ?DEBUG("IsInteresting ~p.", [IsInteresting]),
            case IsInteresting of
                true -> 
                    SRResource = ejabberd_odbc:escape(RLResource),
                    SData = ejabberd_odbc:escape(term_to_binary(Packet)),
                    SDir = encode_direction(Dir),
                    FromLJID = jlib:jid_tolower(FromJID),
                    FromSJID = ejabberd_odbc:escape(jlib:jid_to_string(FromLJID)),
                    archive_message(LServer, BareSLJID, BareSRJID, SRResource, SDir, FromSJID, SData);
%                    archive_message(LServer, SUser, BareSRJID, SRResource, SDir,
%                                    FromSJID, SData);
                false -> ok
            end,
            ok;
        false -> ok
    end.

-spec has_subtag(Packet::#xmlelement{}, Type::list()) -> boolean().
has_subtag(Packet, Type) ->
    case xml:get_subtag(Packet, Type) of
        false -> false;
        _ -> true
    end.

%% @doc Check, that the stanza is a message with body.
%% Servers SHOULD NOT archive messages that do not have a <body/> child tag.
-spec is_complete_message(Packet::#xmlelement{}) -> boolean().
is_complete_message(Packet=#xmlelement{name = "message"}) ->
    case xml:get_tag_attr_s("type", Packet) of
    Type when Type == "";
              Type == "normal";
              Type == "chat";
              Type == "groupchat" ->
        has_subtag(Packet, "body") orelse has_subtag(Packet, "allow-permanent-storage");
    %% Skip <<"error">> type
    _ -> false
    end;
is_complete_message(_) -> false.


%% @doc Form `<forwarded/>' element, according to the XEP.
-spec wrap_message(Packet::elem(), QueryID::list(),
                   MessageUID::term(), DateTime::calendar:datetime(), FromJID::jid()) ->
        Wrapper::elem().
wrap_message(Packet, QueryID, MessageUID, DateTime, FromJID) ->
    #xmlelement{
        name = "message",
        attrs = [],
        children = [result(QueryID, MessageUID), forwarded(Packet, DateTime, FromJID)]}.

-spec forwarded(elem(), calendar:datetime(), jid()) -> elem().
forwarded(Packet, DateTime, FromJID) ->
    #xmlelement{
        name = "forwarded",
        attrs = [{"xmlns", "urn:xmpp:forward:0"}],
        children = [delay(DateTime, FromJID), Packet]}.

-spec delay(calendar:datetime(), jid()) -> elem().
delay(DateTime, FromJID) ->
    jlib:timestamp_to_xml(DateTime, utc, FromJID, "").


%% @doc This element will be added in each forwarded message.
result(QueryID, MessageUID) ->
    %% <result xmlns='urn:xmpp:mam:tmp' queryid='f27' id='28482-98726-73623' />
    #xmlelement{
        name = "result",
        attrs = [{"xmlns", ?NS_MAM},
                 {"queryid", QueryID},
                 {"id", MessageUID}],
        children = []}.


%% @doc This element will be added into "iq/query".
-spec result_set(FirstId, LastId, FirstIndexI, CountI) -> elem() when
    FirstId :: list() | undefined,
    LastId  :: list() | undefined,
    FirstIndexI :: non_neg_integer() | undefined,
    CountI      :: non_neg_integer().
result_set(FirstId, LastId, FirstIndexI, CountI) ->
    %% <result xmlns='urn:xmpp:mam:tmp' queryid='f27' id='28482-98726-73623' />
    FirstEl = [#xmlelement{name = "first",
                           attrs = [{"index", integer_to_list(FirstIndexI)}],
                           children = [#xmlcdata{cdata = FirstId}]
                          }
               || FirstId =/= undefined],
    LastEl = [#xmlelement{name = "last",
                           attrs = [],
                           children = [#xmlcdata{cdata = LastId}]
                          }
               || LastId =/= undefined],
    CountEl = #xmlelement{
            name = "count",
            children = [#xmlcdata{cdata = integer_to_list(CountI)}]},
     #xmlelement{
        name = "set",
        attrs = [{"xmlns", ?NS_RSM}],
        children = FirstEl ++ LastEl ++ [CountEl]}.

result_query(SetEl) ->
     #xmlelement{
        name = "query",
        attrs = [{"xmlns", ?NS_MAM}],
        children = [SetEl]}.

-spec result_prefs(DefaultMode, AlwaysJIDs, NeverJIDs) -> ResultPrefsEl when
    DefaultMode :: list(),
    AlwaysJIDs  :: [list()],
    NeverJIDs   :: [list()],
    ResultPrefsEl :: elem().
result_prefs(DefaultMode, AlwaysJIDs, NeverJIDs) ->
    AlwaysEl = #xmlelement{name = "always",
                           children = encode_jids(AlwaysJIDs)},
    NeverEl  = #xmlelement{name = "never",
                           children = encode_jids(NeverJIDs)},
    #xmlelement{
       name = "prefs",
       attrs = [{"xmlns",?NS_MAM}, {"default", DefaultMode}],
       children = [AlwaysEl, NeverEl]
    }.

encode_jids(JIDs) ->
    [#xmlelement{name = "jid",
                 children = [#xmlcdata{cdata = JID}]}
     || JID <- JIDs].


-spec parse_prefs(PrefsEl) -> {DefaultMode, AlwaysJIDs, NeverJIDs} when
    PrefsEl :: elem(),
    DefaultMode :: list(),
    AlwaysJIDs  :: [list()],
    NeverJIDs   :: [list()].
parse_prefs(El=#xmlelement{name = "prefs", attrs = Attrs}) ->
    {value, Default} = xml:get_attr("default", Attrs),
    AlwaysJIDs = parse_jid_list(El, "always"),
    NeverJIDs  = parse_jid_list(El, "never"),
    {Default, AlwaysJIDs, NeverJIDs}.

parse_jid_list(El, Name) ->
    case xml:get_subtag(El, Name) of
        false -> [];
        #xmlelement{children = JIDEls} ->
            [xml:get_tag_cdata(JIDEl) || JIDEl <- JIDEls]
    end.

send_message(From, To, Mess) ->
    ejabberd_sm:route(From, To, Mess).


is_jid_in_user_roster(LServer, LUser, JID) ->
    {Subscription, _Groups} =
    ejabberd_hooks:run_fold(
        roster_get_jid_info, LServer,
        {none, []}, [LUser, LServer, JID]),
    Subscription == from orelse Subscription == both.


behaviour(LServer, SUser, SJID, BareSJID) ->
    case query_behaviour(LServer, SUser, SJID, BareSJID) of
        {selected, ["behaviour"], [{Behavour}]} ->
            case Behavour of
                "A" -> always;
                "N" -> never;
                "R" -> roster
            end;
        _ -> always %% default for everybody
    end.

query_behaviour(LServer, SUser, SJID, BareSJID) ->
    Result =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT behaviour "
       "FROM mam_config "
       "WHERE local_username='", SUser, "' "
         "AND (remote_jid='' OR remote_jid='", SJID, "'",
               case BareSJID of
                    SJID -> "";
                    _    -> [" OR remote_jid='", BareSJID, "'"]
               end,
         ") "
       "ORDER BY remote_jid DESC "
       "LIMIT 1"]),
    ?DEBUG("query_behaviour query returns ~p", [Result]),
    Result.

update_settings(LServer, LUser, DefaultMode, AlwaysJIDs, NeverJIDs) ->
    SUser = ejabberd_odbc:escape(LUser),
    DelQuery = ["DELETE FROM mam_config WHERE local_username = '", SUser, "'"],
    InsQuery = ["INSERT INTO mam_config(local_username, behaviour, remote_jid) "
       "VALUES ", encode_first_config_row(SUser, encode_behaviour(DefaultMode), ""),
       [encode_config_row(SUser, "A", ejabberd_odbc:escape(JID))
        || JID <- AlwaysJIDs],
       [encode_config_row(SUser, "N", ejabberd_odbc:escape(JID))
        || JID <- NeverJIDs]],
    %% Run as a transaction
    {atomic, [DelResult, InsResult]} =
        sql_transaction_map(LServer, [DelQuery, InsQuery]),
    ?DEBUG("update_settings query returns ~p and ~p", [DelResult, InsResult]),
    ok.

encode_first_config_row(SUser, SBehavour, SJID) ->
    ["('", SUser, "', '", SBehavour, "', '", SJID, "')"].

encode_config_row(SUser, SBehavour, SJID) ->
    [", ('", SUser, "', '", SBehavour, "', '", SJID, "')"].

sql_transaction_map(LServer, Queries) ->
    AtomicF = fun() ->
        [ejabberd_odbc:sql_query(LServer, Query) || Query <- Queries]
    end,
    ejabberd_odbc:sql_transaction(LServer, AtomicF).

%% @doc Load settings from the database.
-spec get_prefs(LServer, LUser, GlobalDefaultMode) -> Result when
    LServer     :: server_hostname(),
    LUser       :: literal_username(),
    DefaultMode :: archive_behaviour(),
    GlobalDefaultMode :: archive_behaviour(),
    Result      :: {DefaultMode, AlwaysJIDs, NeverJIDs},
    AlwaysJIDs  :: [literal_jid()],
    NeverJIDs   :: [literal_jid()].
get_prefs(LServer, LUser, GlobalDefaultMode) ->
    SUser = ejabberd_odbc:escape(LUser),
    {selected, _ColumnNames, Rows} =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT remote_jid, behaviour "
       "FROM mam_config "
       "WHERE local_username='", SUser, "'"]),
    decode_prefs_rows(Rows, GlobalDefaultMode, [], []).

decode_prefs_rows([{"", Behavour}|Rows], _DefaultMode, AlwaysJIDs, NeverJIDs) ->
    decode_prefs_rows(Rows, decode_behaviour(Behavour), AlwaysJIDs, NeverJIDs);
decode_prefs_rows([{JID, "A"}|Rows], DefaultMode, AlwaysJIDs, NeverJIDs) ->
    decode_prefs_rows(Rows, DefaultMode, [JID|AlwaysJIDs], NeverJIDs);
decode_prefs_rows([{JID, "N"}|Rows], DefaultMode, AlwaysJIDs, NeverJIDs) ->
    decode_prefs_rows(Rows, DefaultMode, AlwaysJIDs, [JID|NeverJIDs]);
decode_prefs_rows([], DefaultMode, AlwaysJIDs, NeverJIDs) ->
    {DefaultMode, AlwaysJIDs, NeverJIDs}.


archive_message(LServer, SUser, BareSJID, SResource, Direction, FromSJID, SData) ->
    Result =
    ejabberd_odbc:sql_query(
      LServer,
      ["INSERT INTO mam_messages(local_username, remote_bare_jid, "
                                "remote_resource, message, direction, "
                                "from_jid, added_at) "
       "VALUES ('", SUser,"', '", BareSJID, "', '", SResource, "',"
               "'", SData, "', '", Direction, "', '", FromSJID, "', ",
                integer_to_list(current_milliseconds_timestamp()), ")"]),
    ?DEBUG("archive_message query returns ~p", [Result]),
    ok.

remove_user(LServer, SUser) ->
    Result1 =
    ejabberd_odbc:sql_query(
      LServer,
      ["DELETE "
       "FROM mam_config "
       "WHERE local_username='", SUser, "'"]),
    Result2 =
    ejabberd_odbc:sql_query(
      LServer,
      ["DELETE "
       "FROM mam_messages "
       "WHERE local_username='", SUser, "'"]),
    ?DEBUG("remove_user query returns ~p and ~p", [Result1, Result2]),
    ok.

message_row_to_xml({UID,LMilliSeconds,LFromJID,LPacket}, QueryID) ->
    Packet = binary_to_term(list_to_binary(LPacket)),
    FromJID = jlib:string_to_jid(LFromJID),
    MilliSeconds  = list_to_integer(LMilliSeconds),
    DateTime = calendar:now_to_universal_time(milliseconds_to_now(MilliSeconds)),
    wrap_message(Packet, QueryID, UID, DateTime, FromJID).

message_row_to_id({BUID,_,_,_}) ->
    BUID.

%% Each record is a tuple of form 
%% `{"3","1366312523","bob@localhost","res1",string}'.
%% Columns are `["id","added_at","from_jid","message"]'.
-spec extract_messages(LServer, Filter, IOffset, IMax) ->
    [Record] when
    LServer :: server_hostname(),
    Filter  :: filter(),
    IOffset :: non_neg_integer(),
    IMax    :: pos_integer(),
    Record :: tuple().
extract_messages(_LServer, _Filter, _IOffset, 0) ->
    [];
extract_messages(LServer, Filter, IOffset, IMax) ->
    {selected, _ColumnNames, MessageRows} =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT id, added_at, from_jid, message "
       "FROM mam_messages ",
        Filter,
       " ORDER BY added_at, id"
       " LIMIT ",
         case IOffset of
             0 -> "";
             _ -> [integer_to_list(IOffset), ", "]
         end,
         integer_to_list(IMax)]),
    ?DEBUG("extract_messages query returns ~p", [MessageRows]),
    MessageRows.

    %% #rsm_in{
    %%    max = non_neg_integer() | undefined,
    %%    direction = before | aft | undefined,
    %%    id = binary() | undefined,
    %%    index = non_neg_integer() | undefined}
-spec calc_offset(LServer, Filter, PageSize, TotalCount, RSM) -> Offset
    when
    LServer  :: server_hostname(),
    Filter   :: filter(),
    PageSize :: non_neg_integer(),
    TotalCount :: non_neg_integer(),
    RSM      :: #rsm_in{},
    Offset   :: non_neg_integer().
calc_offset(_LS, _F, _PS, _TC, #rsm_in{direction = undefined, index = Index})
    when is_integer(Index) ->
    Index;
%% Requesting the Last Page in a Result Set
calc_offset(_LS, _F, PS, TC, #rsm_in{direction = before, id = ""}) ->
    max(0, TC - PS);
calc_offset(LServer, Filter, PageSize, _TC, #rsm_in{direction = before, id = ID})
    when is_list(ID) ->
    SID = ejabberd_odbc:escape(ID),
    max(0, calc_before(LServer, Filter, SID) - PageSize);
calc_offset(LServer, Filter, _PS, _TC, #rsm_in{direction = aft, id = ID})
    when is_list(ID), byte_size(ID) > 0 ->
    SID = ejabberd_odbc:escape(ID),
    calc_index(LServer, Filter, SID);
calc_offset(_LS, _F, _PS, _TC, _RSM) ->
    0.

%% Zero-based index of the row with UID in the result test.
%% If the element does not exists, the ID of the next element will
%% be returned instead.
%% "SELECT COUNT(*) as "index" FROM mam_messages WHERE id <= '",  UID
-spec calc_index(LServer, Filter, SUID) -> Count
    when
    LServer  :: server_hostname(),
    Filter   :: filter(),
    SUID     :: escaped_message_id(),
    Count    :: non_neg_integer().
calc_index(LServer, Filter, SUID) ->
    {selected, _ColumnNames, [{Index}]} =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT COUNT(*) FROM mam_messages ", Filter, " AND id <= '", SUID, "'"]),
    list_to_integer(Index).

%% @doc Count of elements in RSet before the passed element.
%% The element with the passed UID can be already deleted.
%% "SELECT COUNT(*) as "count" FROM mam_messages WHERE id < '",  UID
-spec calc_before(LServer, Filter, SUID) -> Count
    when
    LServer  :: server_hostname(),
    Filter   :: filter(),
    SUID     :: escaped_message_id(),
    Count    :: non_neg_integer().
calc_before(LServer, Filter, SUID) ->
    {selected, _ColumnNames, [{Index}]} =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT COUNT(*) FROM mam_messages ", Filter, " AND id < '", SUID, "'"]),
    list_to_integer(Index).


%% @doc Get the total result set size.
%% "SELECT COUNT(*) as "count" FROM mam_messages WHERE "
-spec calc_count(LServer, Filter) -> Count
    when
    LServer  :: server_hostname(),
    Filter   :: filter(),
    Count    :: non_neg_integer().
calc_count(LServer, Filter) ->
    {selected, _ColumnNames, [{Count}]} =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT COUNT(*) FROM mam_messages ", Filter]),
    list_to_integer(Count).


-spec prepare_filter(SUser, IStart, IEnd, WithSJID, WithSResource) -> filter()
    when
    SUser   :: escaped_username(),
    IStart  :: milliseconds_timestamp() | undefined,
    IEnd    :: milliseconds_timestamp() | undefined,
    WithSJID :: escaped_jid(),
    WithSResource :: escaped_resource().
prepare_filter(SUser, IStart, IEnd, WithSJID, WithSResource) ->
   ["WHERE local_username='", SUser, "'",
     case IStart of
        undefined -> "";
        _         -> [" AND added_at >= ", integer_to_list(IStart)]
     end,
     case IEnd of
        undefined -> "";
        _         -> [" AND added_at <= ", integer_to_list(IEnd)]
     end,
     case WithSJID of
        undefined -> "";
        _         -> [" AND remote_bare_jid = '", WithSJID, "'"]
     end,
     case WithSResource of
        undefined -> "";
        _         -> [" AND remote_resource = '", WithSResource, "'"]
     end].


%% "maybe" means, that the function may return 'undefined'.
-spec maybe_milliseconds_timestamp(iso8601_datetime_list()) -> milliseconds_timestamp();
                          (<<>>) -> undefined.
maybe_milliseconds_timestamp("") -> undefined;
maybe_milliseconds_timestamp(<<>>) -> undefined;
maybe_milliseconds_timestamp(ISODateTime) ->
    case iso8601_datetime_list_to_timestamp(ISODateTime) of
        undefined -> undefined;
        Stamp -> now_to_milliseconds(Stamp)
    end.

-spec current_milliseconds_timestamp() -> milliseconds_timestamp().
current_milliseconds_timestamp() ->
    now_to_milliseconds(os:timestamp()).

-spec now_to_milliseconds(erlang:timestamp()) -> milliseconds_timestamp().
now_to_milliseconds(Now) ->
    timer:now_diff(Now, {0,0,0}).

-spec milliseconds_to_now(milliseconds_timestamp()) -> erlang:timestamp().
milliseconds_to_now(MilliSeconds) when is_integer(MilliSeconds) ->
    {MilliSeconds div 1000000000000, (MilliSeconds div 1000000) rem 1000000, MilliSeconds rem 1000}.

%% @doc Returns time in `now()' format.
-spec iso8601_datetime_list_to_timestamp(iso8601_datetime_list()) ->
    erlang:timestamp().
iso8601_datetime_list_to_timestamp(DateTime) when is_list(DateTime) ->
    jlib:datetime_string_to_timestamp(DateTime).


-spec maybe_integer(binary() | list()) -> integer() | undefined.
maybe_integer(Bin) -> maybe_integer(Bin, undefined).

maybe_integer("", Def) -> Def;
maybe_integer(<<>>, Def) -> Def;
maybe_integer(Bin, _Def) when is_binary(Bin) ->
    list_to_integer(binary_to_list(Bin));
maybe_integer(Bin, _Def) when is_list(Bin) ->
    list_to_integer(Bin).


get_one_of_path_bin(Elem, List) ->
    get_one_of_path(Elem, List, "").

get_one_of_path(Elem, [H|T], Def) ->
    case xml:get_path_s(Elem, H) of
        Def -> get_one_of_path(Elem, T, Def);
        Val  -> Val
    end;
get_one_of_path(_Elem, [], Def) ->
    Def.
