import posix, strutils
from net import IpAddress, parseIPAddress
from dynlib import LibHandle, symAddr


const v2sig* = "\c\n\c\n\x00\c\nQUIT\n"

proc c_memcmp(a, b: pointer, size: csize): cint {.importc: "memcmp", header: "<string.h>", noSideEffect.}

type
  HeaderV2_IPV4 {.union.} = object
    src_addr: uint32
    dst_addr: uint32
    src_port: uint16
    dst_port: uint16

  HeaderV2_IPV6 = object
    src_addr: array[16, uint8]
    dst_addr: array[16, uint8]
    src_port: uint16
    dst_port: uint16

  HeaderV2_UNIX = object
    src_addr: array[108, uint8]
    dst_addr: array[108, uint8]

  HeaderV2_Addr {.union.} = object
    ip4: HeaderV2_IPV4
    ip6: HeaderV2_IPV6
    unx: HeaderV2_UNIX

  HeaderV2 = object
    sig: array[12, uint8]
    ver_cmd: uint8
    fam: uint8
    length: uint16
    address: HeaderV2_Addr

  Header {.union.} = object
    v1: array[108, char]
    v2: HeaderV2

template done() =
  ##  we need to consume the appropriate amount of data from the socket
  while true:
    result = recv(fd, addr(hdr), size, 0)
    if not (result == -1 and errno == EINTR): break
    return if (result >= 0): 1 else: -1

proc pp_handshake*(fd: SocketHandle, sa: ptr SockAddr, sl: ptr Socklen): int =
  var
    size: int
    hdr: Header

  while true:
    result = recv(fd, addr hdr, sizeof(hdr), 0)
    if not (result == -1 and errno == EINTR):
      break
  if result == -1:
    return if (errno == EAGAIN): 0 else: -1

  if result >= 16 and c_memcmp(addr hdr.v2, v2sig.cstring, 12) == 0 and (hdr.v2.ver_cmd and 0xF0) == 0x20:
    size = 16 + ntohs(hdr.v2.length).int
    if result < size:
      return -1
    case hdr.v2.ver_cmd and 0xF
    of 0x1: # PROXY command
      case hdr.v2.fam
      of 0x11: # TCPv4
        var src: Sockaddr_in
        src.sin_family = AF_INET.TSa_Family
        src.sin_addr.s_addr = hdr.v2.address.ip4.src_addr
        src.sin_port = hdr.v2.address.ip4.src_port
        copyMem(sa, addr src, sl[])
        done()
      of 0x21: # TCPv6
        var src6: Sockaddr_in6
        src6.sin6_family = AF_INET6.TSa_Family
        copyMem(addr src6.sin6_addr, addr hdr.v2.address.ip6.src_addr, 16)
        src6.sin6_port = hdr.v2.address.ip6.src_port
        copyMem(sa, addr src6, sl[])
        done()
      else:
        discard
    of 0x0: # LOCAL command
      discard
    else:
      return -1
  elif result >= 8 and hdr.v1[0..4] == @['P', 'R', 'O', 'X', 'Y']:
    let backslash_c = hdr.v1.find('\c')
    if backslash_c == -1 or hdr.v1[backslash_c + 1] != '\n':
      return -1
    hdr.v1[backslash_c] = '\0'
    let
      buffer = $cast[cstring](addr hdr.v1)
      params = splitWhitespace(buffer)
    if params[1] == "TCP4":
      var
        src: Sockaddr_in
        ip = parseIPAddress(params[2])
      src.sin_family = AF_INET.TSa_Family
      src.sin_addr.s_addr = cast[uint32](ip.address_v4)
      src.sin_port = htons(parseInt(params[4]).uint16)
      copyMem(sa, addr src, sl[])
      return buffer.len
    elif params[1] == "TCP6":
      var
        src6: Sockaddr_in6
        ip = parseIPAddress(params[2])
      src6.sin6_family = AF_INET6.TSa_Family
      copyMem(addr src6.sin6_addr, addr ip.address_v6, 16)
      src6.sin6_port = htons(parseInt(params[4]).uint16)
      copyMem(sa, addr src6, sl[])
      return buffer.len
    else:
      return -1
  else:
    ##  Wrong protocol
    return -1

when isMainModule:
  type AcceptProc = proc(a1: SocketHandle, a2: ptr SockAddr, a3: ptr Socklen): SocketHandle {.cdecl.}
  var
    RTLD_NEXT {.importc: "RTLD_NEXT", header: "<dlfcn.h>".}: LibHandle
    real_accept: AcceptProc

  proc pp_accept*(a1: SocketHandle, a2: ptr SockAddr, a3: ptr Socklen): SocketHandle {.exportc:"accept",cdecl.} =
    result = real_accept(a1, a2, a3)
    if result.int != -1:
      if pp_handshake(result, a2, a3) <= 0:
        echo "[PROXY] connection 0x", toHex(result.int), " invalid proxy-protocol header"
        result = SocketHandle(-1)

  let accept_ptr = symAddr(RTLD_NEXT, "accept")
  if accept_ptr == nil:
    quit "[PROXY] cannot find accept proc"

  real_accept = cast[AcceptProc](accept_ptr)
  echo "[PROXY] hook accept OK"