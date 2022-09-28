import posix, asyncnet, asyncdispatch
import ../src/proxyproto

proc processClient(client: AsyncSocket) {.async.} =
  while true:
    let line = await client.recvLine()
    await client.send(line & "\c\L")
    var
      slen: SockLen
      src: SockAddr_in

    #if getpeername(client.getFd(), cast[ptr SockAddr](addr src), addr slen) == 0:
      #echo "remote ", inet_ntoa(src.sin_addr), ":", htons(src.sin_port), " : ", line
    echo "remote ", client.getPeerAddr(), " : ", line


proc serve() {.async.} =
  var server = newAsyncSocket()
  server.bindAddr(Port(4444))
  server.listen()

  while true:
    try:
      let client = await server.accept()
      discard processClient(client)
    except:
      discard


asyncCheck serve()
runForever()
