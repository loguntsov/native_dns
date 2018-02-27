-module(native_dns_test).

-author("Sergey Loguntsov <loguntsov@gmail.com>").

%% API
-compile(export_all).

t() ->
  { ok, P } = native_dns_client:start_link(0),
  {ok, [_IPS], _Timeout } = native_dns_client:query(P, 'A', <<"ya.ru">>, <<"8.8.8.8">>, 5000),
  {ok, [_IPS], _Timeout } = native_dns_client:query(P, 'MX', <<"ya.ru">>, <<"8.8.8.8">>, 5000).

