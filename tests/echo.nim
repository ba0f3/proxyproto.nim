import posix, asyncnet, asyncdispatch

proc processClient(client: AsyncSocket) {.async.} =
  while true:
    let line = await client.recvLine()
    await client.send(line & "\c\L")
    var
      slen: SockLen
      src: SockAddr_in

    if getpeername(client.getFd(), cast[ptr SockAddr](addr src), addr slen) == 0:
      echo "remote ip ", inet_ntoa(src.sin_addr)


proc serve() {.async.} =
  var server = newAsyncSocket()
  server.bindAddr(Port(6001))
  server.listen()

  while true:
    let client = await server.accept()
    discard processClient(client)

asyncCheck serve()
runForever()
