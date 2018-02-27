-module(native_dns_time).

-author("Sergey Loguntsov <loguntsov@gmail.com>").

%% API
-export([
	now_sec/0, now_ms/0, now_micro/0,
	unix_time/1, unix_time_ms/1, unix_time_micro/1
]).

unix_time({MegaSec, Sec, _}) ->
	MegaSec * 1000 * 1000 + Sec.

unix_time_micro({MegaSec, Sec, MicroSec}) ->
	(MegaSec * 1000 * 1000 + Sec ) * 1000 * 1000 + MicroSec.

unix_time_ms(Time) ->
	unix_time_micro(Time) div 1000.

now_sec() ->
	os:system_time(second).

now_ms() ->
	os:system_time(millisecond).

now_micro() ->
	os:system_time(microsecond).