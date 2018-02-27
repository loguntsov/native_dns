-module(native_dns_query).

-author("Sergey Loguntsov <loguntsov@gmail.com>").

-export([
  query/5, parse_packet/2,
  decode_response/1
]).

-define(LOG(Fmt, Data), lager:info(Fmt, Data)).

-type dns_type() :: 'A' | 'NS' | 'CNAME' | 'MX' .

-export_type([
  dns_type/0
]).

-record(record, {
  type :: atom(),
  class,
  ttl,
  data
}).

-record(question, {
  domain,
  type,
  class
}).

-record(dnsh, {
  id, opcode, aa, tc, rd, ra, rcode, qdcount, ancount, authrs, addrs
}).

enc_string(Str) when is_list(Str) ->
  enc_string(iolist_to_binary(Str));
enc_string(Str) ->
    Len = byte_size(Str),
    <<Len:8, Str/binary>>.

dec_strings(Str, <<0:8, Rest/binary>>, Pos, _)                   ->  {Str, Rest, Pos + 1};
dec_strings(Str, <<>>, Pos, _)                                   ->  {Str, <<>>, Pos};
dec_strings(Str, <<2#11:2, Offset:14, Rest/binary>>, Pos, Packet) ->
  { Str0, _, _ } = dec_strings(Str, binary:part(Packet, Offset, size(Packet) - Offset ), Offset, Packet),
  { Str0, Rest, Pos + 2 };
dec_strings(Str, <<L:8, StrData:L/binary, Rest/binary>>, Pos, Packet) ->
    Strings = Str ++ [binary_to_list(StrData)],
    dec_strings(Strings, Rest, Pos + L + 1, Packet);

dec_strings(Str, Rest, Pos, Packet) ->
  error(bad_packet, [ Str, Rest, Pos, Packet ]).

make_query(ID, Name, Type) ->
    HDR = <<ID:2/binary, 0:1, 0:4, 0:1, 0:1, 1:1, 0:1, 0:3, 0:4, 1:16, 0:16, 0:16, 0:16>>,
    QUERYSTR = [ enc_string(STR) || STR <- string:tokens(Name, ".") ],
    TypeCode = case Type of
      'A' -> 1;
      'NS' -> 2;
      'CNAME' -> 5;
      'MX' -> 15
    end,
    iolist_to_binary([HDR, QUERYSTR, <<0:8, TypeCode:16, 1:16>>]).

dec_record(<<3:2, _:6, _:8, 1:16, Class:16, TTL:32,
             RDLength:16, RData:RDLength/binary, Rest/binary>>, Pos, Packet) ->
    [#record{ type = type_A, class = Class, ttl = TTL, data = RData }|dec_record(Rest, Pos+12+RDLength, Packet)];

dec_record(<<3:2, _:6, _:8, 5:16, Class:16, TTL:32,
             RDLength:16, RData:RDLength/binary, Rest/binary>>, Pos, Packet) ->
    {Str, _, _} = dec_strings([], RData, Pos+12, Packet),
    [#record{ type = type_CNAME, class = Class, ttl = TTL, data = Str }|dec_record(Rest, Pos+12+RDLength, Packet)];

dec_record(<<3:2, _:6, _:8, 15:16, Class:16, TTL:32,
             RDLength:16/unsigned-integer, RData:RDLength/binary, Rest/binary>>,  Pos, Packet) ->
    %%?LOG("MX ~p", [ P ]),
    %% binpp:pprint(P),
    case RDLength =:= 0 of
      true -> dec_record(Rest, Pos+12+RDLength, Packet);
      false ->
        [#record{ type = type_MX, class = Class, ttl = TTL, data = parse_mx(RData, Pos, Packet)}|dec_record(Rest, Pos+12+RDLength, Packet)]
    end;

dec_record(<<3:2, _:6, _:8, 6:16, Class:16, TTL:32,
             RDLength:16/unsigned-integer, RData:RDLength/binary, Rest/binary>>, Pos, Packet) ->
    [#record{ type = type_SOA, class = Class, ttl = TTL, data = dec_strings([], RData, Pos+12, Packet)}|dec_record(Rest, Pos+12+RDLength, Packet)];

dec_record(<<3:2, _:6, _:8, T:16, Class:16, TTL:32,
             RDLength:16/unsigned-integer, RData:RDLength/binary, Rest/binary>>, Pos, Packet) ->
    [#record{ type = { unknown, T }, class = Class, ttl = TTL, data = RData }|dec_record(Rest, Pos+12+RDLength, Packet)];

dec_record(<<>>, _Pos, _) -> [];
dec_record(B, Pos, _) -> [{ Pos, B }].

parse_mx(<<Weight:16/unsigned-integer, Rest/binary>>, Pos, Packet) ->
  { Strings, _ , _ } = dec_strings([], Rest, Pos + 2, Packet),
  { Weight, Strings }.

%% http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm --- format of packets

decode_response(<<ID:16, 1:1, OPCODE:4, AA:1, TC:1, RD:1, RA:1, _:3, % <--- Sometimes some servers don't return 0 - so it was ignored
                 RCode:4, QDCount:16, ANCount:16, AUTHRS:16, ADDRS:16, Rest/binary>> = Packet) ->
    %% binpp:pprint(Packet),
    {Strings, Rest2, NewPos} = dec_strings([], Rest, 12, Packet ),
    % ?LOG("A ~p", [ A ]),
    case Rest2 of
      <<Type:16, Class:16, Rest3/binary>> ->
        { ok, #{dnsh => #dnsh{  id = ID, opcode = OPCODE, aa = AA, tc = TC, rd = RD, ra = RA, rcode = RCode, qdcount = QDCount,
                                ancount = ANCount, authrs = AUTHRS, addrs = ADDRS },
          question => #question{ domain = Strings, type = Type, class = Class},
          response => dec_record(Rest3,NewPos, Packet)
        }};
      <<>> ->
        undefined;
      _ -> error(bad_packet, [ Packet ])
    end;

decode_response(Packet) ->
  error(bad_packet, [ Packet ]).

query(Socket, PacketId, Type, Name, Server) when is_binary(Name) ->
  query(Socket, PacketId, Type, binary_to_list(Name), Server);

query(Socket, PacketId, Type, Name, Server) when is_binary(Server) ->
  query(Socket, PacketId, Type, Name, binary_to_list(Server));

query(Socket, PacketId, Type, Name, Server) when is_binary(PacketId), size(PacketId) =:= 2 ->
    Q = make_query(PacketId, Name, Type),
    %%binpp:pprint(Q),
    %%io:format("~n~n"),
    try
        gen_udp:send(Socket, Server, 53, Q)
    catch
        E:R -> error({E,R}, [ Socket, Server, PacketId, Type, Name, Q ])
    end.

parse_packet(Type, Packet = <<ID:16, _/binary>>) ->
  DecodedPacket = try
    decode_response(Packet)
  catch
    error:bad_packet ->
      %lager:warning("Bad packet ~p. Stacktrace: ~p", [ Packet, erlang:get_stacktrace() ]),
      undefined
  end,
  { ID, convert_response(Type, DecodedPacket)}.

dns_name(Strings) ->
  iolist_to_binary(lists:foldl(fun
    (Str, []) -> [Str];
    (Str, Acc) ->
      Acc ++ "." ++ Str
  end, [], Strings)).

convert_response(_, undefined) -> undefined;

convert_response('MX', { ok, #{ dnsh := DnsInfo, response := Response }}) ->
  Items0 = lists:filter(fun(#record{ type = type_MX }) -> true; (_) -> false end, Response),
  Items1 = lists:sublist(Items0, DnsInfo#dnsh.ancount),
  R = lists:map(fun(Item) ->
    { Weight, Str } = Item#record.data,
    { dns_name(Str), Weight }
  end, Items1),
  { ok, R };

convert_response('A', { ok, #{ dnsh := DnsInfo, response := Response }}) ->
  Items0 = lists:filter(fun(#record{ type = type_A }) -> true; (_) -> false end, Response),
  Items1 = lists:sublist(Items0, DnsInfo#dnsh.ancount),
  R = lists:map(fun(Item) ->
    Ip = case Item#record.data of
      <<A:8/unsigned-integer, B:8/unsigned-integer, C:8/unsigned-integer, D:8/unsigned-integer>> ->
        inet:ntoa({A, B, C, D});
      <<A:16/unsigned-integer, B:16/unsigned-integer, C:16/unsigned-integer, D:16/unsigned-integer,
        E:16/unsigned-integer, F:16/unsigned-integer, G:16/unsigned-integer, H:16/unsigned-integer>> ->
        inet:ntoa({A,B,C,D,E,F,G,H})
    end,
    iolist_to_binary(Ip)
  end, Items1),
  { ok, R };


convert_response(_Type, Response) -> Response.
