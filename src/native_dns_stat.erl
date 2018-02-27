-module(native_dns_stat).
-author("Sergey Loguntsov <loguntsov@gmail.com>").

-behaviour(gen_server).

-define(ATTEMPTS_RANDOM, 5).
%% API
-export([
  start_link/3, start_link/2, child_spec/3, child_spec/2,
  fail/3, success/3,
  stat/2, total_stat/1,
  get_random/1,
  set_threshold/2
]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).
-define(TICK, 5000).

-record(st, {
  fails = 1 :: pos_integer(),
  fails_timeout = 0 :: pos_integer(),
  success = 8 :: pos_integer(),
  success_timeout = 0 :: pos_integer(),
  quality = 10 :: pos_integer()
}).

-record(state, {
  dns = gb_trees:empty() :: gb_trees:tree(binary(), #st{}),
  count = 0 :: pos_integer(),
  tuple = {} :: tuple(),
  quality = 0.8 :: float(),
  changed = false :: boolean(),
  deleted = []
}).

start_link(Pool, Number) ->
  start_link(Pool, Number, []).
start_link(Pool, Number, DnsList) ->
  Self = self(),
  Pid = spawn_link(fun() ->
    Pool = ets:new(Pool, [ named_table, protected, set, { read_concurrency, true }, { write_concurrency, false } ]),
    Queue = list_to_tuple([ [] || _ <- lists:seq(1, Number) ]),
    NewQueue = lists:foldl(fun(Dns, Acc) ->
      Index = erlang:phash2(Dns, Number)+1,
      setelement(Index, Acc, [ Dns | element(Index, Acc)])
    end, Queue, DnsList),
    Workers = lists:map(fun(SubDnsList) ->
      { ok, Pid } = gen_server:start_link(?MODULE, [ SubDnsList ], []),
      Pid
    end, tuple_to_list(NewQueue)),
    ets:insert(Pool, { pids, list_to_tuple(Workers) }),
    Self ! '$done',
    receive
      {'EXIT', Reason } -> { exit, Reason }
    end
  end),
  receive
    '$done' -> ok
  end,
  { ok, Pid }.

child_spec(Pool, Number) ->
  child_spec(Pool, Number, []).
child_spec(Pool, Number, DnsList) ->
  { Pool, { ?MODULE, start_link, [ Pool, Number, DnsList ] }, permanent, brutal_kill, worker, [ ?MODULE ] }.

pids(Pool) ->
  [{ _, Pids}] = ets:lookup(Pool, pids),
  Pids.

pid(Pool, Dns) ->
  Pids = pids(Pool),
  element(erlang:phash2(Dns, erlang:size(Pids))+1, Pids).

success(Pool, Dns, Timeout) ->
  gen_server:cast(pid(Pool, Dns), { action, success, Dns, Timeout }).

fail(Pool, Dns, Timeout) ->
  gen_server:cast(pid(Pool, Dns), { action, fail, Dns, Timeout }).

set_threshold(Pool, Timeout) ->
  Pids = tuple_to_list(pids(Pool)),
  lists:foreach(fun(Pid) ->
    gen_server:cast(Pid, { set_threshold, Timeout })
  end, Pids).

stat(Pool, Dns) ->
  gen_server:call(pid(Pool, Dns), stat).

total_stat(Pool) ->
  Pids = tuple_to_list(pids(Pool)),
  Results = pmap:pmap(fun(Pid) ->
    { ok, State } = gen_server:call(Pid, get_state),
    StList = gb_trees:to_list(State#state.dns),
    GoodQ = length(lists:filter(fun({_, St}) -> is_good(St, State) end, StList)),
    BadQ = length(lists:filter(fun({_, St}) -> not(is_good(St, State)) end, StList)),
    { GoodQ, BadQ }
  end, Pids, length(Pids)),
  lists:foldl(fun({ GoodQ, BadQ }, { Good, Bad }) ->
    { Good + GoodQ, Bad + BadQ }
  end, { 0, 0 }, Results).

get_random(Pool) ->
  Pid = pid(Pool, rand:uniform(10000000)),
  case gen_server:call(Pid, get_random, infinity) of
    nothing -> get_random(Pool);
    Any -> Any
  end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([ DnsList ]) ->
  List = lists:usort(DnsList),
  {ok, tick(make_tuple(#state{
    dns = gb_trees:from_orddict([{ Dns, #st{}} || Dns <- List ])
  }))}.

handle_call({stat, Dns}, _From, State) ->
  case gb_trees:lookup(Dns, State#state.dns) of
    { value, St } ->
      { reply, { ok, St }, State };
    none ->
      { reply, undefined, State }
  end;

handle_call( get_random, _From, State ) ->
  { Dns, NewState } = process_random(?ATTEMPTS_RANDOM, State),
  { reply, Dns, NewState };

handle_call(get_state, _From, State) ->
  { reply, { ok, State }, State };

handle_call(_Request, _From, State) ->
  {reply, ok, State}.
handle_cast({action, Type, Dns, Timeout}, State) ->
  NewState = process_action(Dns, Type, Timeout, State),
  { noreply, NewState };

handle_cast(_Request, State) ->
  {noreply, State}.

handle_info(tick, State) ->
  NewState = case State#state.changed orelse State#state.deleted =/= [] of
    true ->
      make_tuple(State#state{
        dns = gb_trees:from_orddict([ Item || { Dns, _} = Item <- gb_trees:to_list(State#state.dns), not(lists:member(Dns, State#state.deleted))]),
        deleted = [],
        changed = false
      });
    false ->
      State
  end,
  { noreply, tick(NewState) };

handle_info(_Info, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

change_stat(success, Timeout, Stat) ->
  Stat#st{
    success = Stat#st.success + 1,
    success_timeout = Stat#st.success_timeout +  Timeout
  };

change_stat(fail, Timeout, Stat) ->
  Stat#st{
    fails = Stat#st.success + 1,
    fails_timeout = Stat#st.success_timeout + Timeout
  }.

del_stat(Dns, State) ->
  case lists:member(Dns, State#state.deleted) of
    false ->
      State#state{
        deleted = [ Dns | State#state.deleted ]
      };
    true ->
      State
  end.

make_tuple(State) ->
  Tuple = list_to_tuple([ Dns0 || { Dns0, St } <- gb_trees:to_list(State#state.dns), is_good(St, State)]),
  State#state{
    tuple = Tuple,
    count = size(Tuple)
  }.

get_stat(Dns, State) ->
  case gb_trees:lookup(Dns, State#state.dns) of
    { value, Stat } ->
      { ok, Stat, State };
    none ->
      nothing
  end.

quality(Stat) ->
  ( Stat#st.success ) / ( Stat#st.fails ).

is_good(St, State) ->
  quality(St) >= State#state.quality.

process_action(Dns, Type, Timeout, State) ->
  case get_stat(Dns, State) of
    { ok, Stat, NewState } ->
      NewStat = change_stat(Type, Timeout, Stat),
      NewState#state{
        dns = gb_trees:update(Dns, NewStat, NewState#state.dns)
      };
    nothing ->
      State
  end.

process_random(_, State = #state{ count = C }) when C =:= 0 ->
  { nothing, State };
process_random(_, State = #state{ count = C }) when C < 0 -> error(bad_state, [ State ]);
process_random(Attempt, State) when Attempt > 0 ->
  Random = rand:uniform(State#state.count),
  Dns = element(Random, State#state.tuple),
  { ok, St, NewState } = get_stat(Dns, State),
  case is_good(St, State) of
    true -> {{ ok, Dns }, NewState };
    _ ->
      process_random(Attempt - 1, del_stat(Dns, NewState))
  end;
process_random(_, State) ->
  { nothing, State }.

tick(State) ->
  erlang:send_after(?TICK, self(), tick),
  State.


