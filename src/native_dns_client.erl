-module(native_dns_client).

-behaviour(gen_server).
-author("Sergey Loguntsov <loguntsov@gmail.com>").

%% API
-export([
  start_link/1, stop/1,
  query/4, query/5
]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).
-define(TIMEOUT, 5000).

-record(query, {
  ref :: reference(),
  type :: native_dns_query:dns_type(),
  name :: binary(),
  server :: binary(),
  timeout :: native_dns_time:time(),
  packet_id :: binary(),
  from :: term(),
  start_time :: native_dns_time:time()
}).

-record(state, {
  socket :: port(),
  queries = [] :: [#query{}]
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Port) ->
  gen_server:start_link(?MODULE, [ Port ], []).

query(Pid, Type, Name, Server) ->
  query(Pid, Type, Name, Server, 5000).

query(Pid, Type, Name, Server, Timeout) when Server =/= <<>>, Server =/= [] ->
  Ref = make_ref(),
  Time = native_dns_time:now_ms() + Timeout,
  try
    Query = #query{
      ref = Ref,
      type = Type,
      name = Name,
      server = Server,
      timeout = Time
    },
    gen_server:call(Pid, Query, Timeout)
  catch
    exit:{timeout,_ } ->
      gen_server:cast(Pid, { delete, Ref, timeout }),
      { error, timeout };
    Error:Reason ->
      gen_server:cast(Pid, { delete, Ref, error }),
      erlang:raise(Error, Reason, erlang:get_stacktrace())
  end.

stop(Pid) ->
  gen_server:cast(Pid, stop).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([ Port ]) ->
  case gen_udp:open(Port, [ binary, { active, true }, {buffer,212992},{sndbuf,212992},{recbuf,212992}]) of
    { ok, Socket } ->
      link(Socket),
      {ok, #state{
        socket = Socket
      }, ?TIMEOUT};
    { error, eaddrinuse} ->
      error({ port_used, Port })
  end.

handle_call(#query{} = Query, From, State) ->
  NewState = do_query(Query, From, State),
  {noreply, NewState, ?TIMEOUT}.

handle_cast({ delete, Ref, Reason }, State) ->
  NewState = do_delete(Ref, State, Reason),
  {noreply, NewState, ?TIMEOUT};

handle_cast(stop, State) ->
  { stop, normal, State }.

handle_info({udp, _Socket, _Ip, _Port, Packet}, State) ->
  NewState = do_parse(Packet,State),
  {noreply, NewState, ?TIMEOUT};

handle_info(timeout, State) ->
  { noreply, State, hibernate };

handle_info(_, State) ->
  { noreply, State, ?TIMEOUT }.

terminate(_Reason, State) ->
  gen_udp:close(State#state.socket),
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

generate_id(Ref, State) ->
  <<ID:2/binary, _/binary>> = crypto:hash(md5, term_to_binary(Ref)),
  case lists:keymember(ID, #query.packet_id, State#state.queries) of
    true ->
      generate_id(make_ref(), State);
    false -> ID
  end.

do_query(Query = #query{ timeout = Time, ref = Ref, type = Type, name = Name, server = Server }, From, State) ->
  Now = native_dns_time:now_ms(),
  case Now > Time of
    true ->
      State;
    false ->
      ID = generate_id(Ref, State),
      case native_dns_query:query(State#state.socket, ID, Type, Name, Server) of
        ok ->
          NewQuery = Query#query{
            packet_id = ID,
            start_time = Now,
            from = From
          },
          NewState = State#state{
            queries = [NewQuery | State#state.queries ]
          },
          NewState;
        { error, _ } = Error ->
          gen_server:reply(From, Error),
          State
      end
  end.

do_parse(Packet = <<ID:2/binary, _/binary>>, State) ->
  %%binpp:pprint(Packet),
  %%io:format("~n~n"),
  case lists:keyfind(ID, #query.packet_id, State#state.queries) of
    false ->
      State;
    #query{ type = Type, name = Name, from = From, start_time = StartTime }->
      Now = native_dns_time:now_ms(),
      { _, Result } = native_dns_query:parse_packet(Type, Packet),
      SentResult = case Result of
        { ok, R } -> { ok, R, Now - StartTime };
        undefined -> {{ error, bad_answer}, Now - StartTime }
      end,
      gen_server:reply(From, SentResult),
      NewState = State#state{
        queries = lists:keydelete(ID, #query.packet_id, State#state.queries)
      },
      case SentResult of
        { ok, R0, _ } ->
          Queries = lists:foldl(fun
            (#query{ type = Type0, name = Name0, from = From0, start_time = StartTime0 }, Acc) when Type0 =:= Type, Name0 =:= Name ->
              gen_server:reply(From0, { ok, R0, Now - StartTime0}),
              Acc;
            (Q, Acc) -> [ Q | Acc ]
          end, [], NewState#state.queries),
          NewState#state{
            queries = Queries
          };
        {{error, _}, _ } -> NewState
      end
  end;
do_parse(_, State) -> State.

do_delete(Ref, State, _Reason) ->
  State#state{
    queries = lists:keydelete(Ref, #query.ref, State#state.queries)
  }.