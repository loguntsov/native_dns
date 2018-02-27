-module(native_dns_client_pool).

-author("Sergey Loguntsov <loguntsov@gmail.com>").

%% API
-export([
  start_link/2, child_spec/2,
  pids/1, pid/2
]).

start_link(Pool, Count) when is_integer(Count) ->
  start_link(Pool, [ 0 || _ <- lists:seq(1, Count) ]);

start_link(Pool, Ports) when is_list(Ports) ->
  Self = self(),
  Pid = spawn_link(fun() ->
    Pool = ets:new(Pool, [ named_table, set, protected, { write_concurrency, false }, { read_concurrency, true } ]),
    Pids = lists:map(fun(Port) ->
      { ok, Pid } = native_dns_client:start_link(Port),
      Pid
    end, Ports),
    ets:insert(Pool, { pids, list_to_tuple(Pids) }),
    Self ! '$done',
    receive
      {'EXIT', Reason } -> { exit, Reason }
    end
  end),
  receive
    '$done' -> ok
  end,
  { ok, Pid }.

child_spec(Pool, Ports) ->
  { Pool, { ?MODULE, start_link, [ Pool, Ports ] }, permanent, brutal_kill, worker, [ ?MODULE ] }.

pids(Name) ->
  [{ _, Pids}] = ets:lookup(Name, pids),
  Pids.

pid(Name, Term) ->
  Pids = pids(Name),
  element(erlang:phash2(Term, size(Pids))+1, Pids).


