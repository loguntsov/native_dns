# Native DNS client

It allow you to make many requests per second for DNS servers to resolve DNS-names.
It support A and MX records.


# Usage

```
  { ok, P } = native_dns_client:start_link(0),
  {ok, [_IPS], _Timeout } = native_dns_client:query(P, 'A', <<"ya.ru">>, <<"8.8.8.8">>, 5000),
  {ok, [_IPS], _Timeout } = native_dns_client:query(P, 'MX', <<"ya.ru">>, <<"8.8.8.8">>, 5000).
 ```

You can use one client instance from several parallel working processes.

# License

MIT
