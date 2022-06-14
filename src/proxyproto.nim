import posix
from strutils import parseInt
from net import IpAddress, parseIPAddress
from dynlib import LibHandle, symAddr


const
  v1sig = "PROXY".cstring
  # v2       \c         \n    \c    \n    \0    \c    \n    Q     U     I     T     \n
  v2sig = [0x0D.byte, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]

type
  HeaderV2_IPV4 = object
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

  ParseStep = enum
    SRC_IP
    DST_IP
    SRC_PORT
    DST_PORT

proc pp_handshake*(fd: SocketHandle, sa: ptr SockAddr, sl: ptr Socklen): int  =
  var
    hdr: Header
    src: Sockaddr_in
    src6: Sockaddr_in6

  while true:
    result = recv(fd, addr hdr, sizeof(hdr), 0)
    if not (result == -1 and errno == EINTR):
      break
  if result == -1:
    return if (errno == EAGAIN): 0 else: -1

  if result >= 16 and hdr.v2.sig == v2sig and (hdr.v2.ver_cmd and 0xF0) == 0x20 and result >= 16 + ntohs(hdr.v2.length).int:
    case hdr.v2.ver_cmd and 0xF
    of 0x1: # PROXY command
      case hdr.v2.fam
      of 0x11: # TCPv4
        src.sin_family = AF_INET.TSa_Family
        src.sin_addr.s_addr = hdr.v2.address.ip4.src_addr
        src.sin_port = hdr.v2.address.ip4.src_port
        copyMem(sa, addr src, sl[])
      of 0x21: # TCPv6
        src6.sin6_family = AF_INET6.TSa_Family
        copyMem(addr src6.sin6_addr, addr hdr.v2.address.ip6.src_addr, 16)
        src6.sin6_port = hdr.v2.address.ip6.src_port
        copyMem(sa, addr src6, sl[])
      else:
        return -1
    of 0x0: # LOCAL command
      return -1
    else:
      return -1
  elif result >= 8 and cmpMem(addr hdr, v1sig, 5) == 0:
    let backslash_r = hdr.v1.find('\r')
    if backslash_r == -1 or hdr.v1[backslash_r + 1] != '\n':
      return -1
    hdr.v1[backslash_r] = '\0'
    var
      tmp: array[40, char]
      step = SRC_IP
      idx = 0
      c: char
    if hdr.v1[9] == '4':
      src.sin_family = AF_INET.TSa_Family
      for i in 11..backslash_r:
        c = hdr.v1[i]
        if c == ' ' or c == '\0':
          case step
          of SRC_IP:
            step = DST_IP
            zeroMem(addr tmp, sizeof(tmp))
            src.sin_addr.s_addr = cast[uint32](parseIPAddress($cast[cstring](addr tmp)).address_v4)
          of DST_IP: # temporary ignore destination ip address
            step = SRC_PORT
          of SRC_PORT:
            step = DST_PORT
            zeroMem(addr tmp, sizeof(tmp))
            src.sin_port = htons(parseInt($cast[cstring](addr tmp)).uint16)
            copyMem(sa, addr src, sl[])
            return backslash_r
          of DST_PORT: # temporary ignore destination port
            break
          idx = 0
        else:
          tmp[idx] = c
          inc(idx)
    elif hdr.v1[0] == '6':
      src6.sin6_family = AF_INET6.TSa_Family
      for i in 11..backslash_r:
        c = hdr.v1[i]
        if c == ' ' or c == '\0':
          case step
          of SRC_IP:
            step = DST_IP
            var ip = parseIPAddress($cast[cstring](addr tmp))
            zeroMem(addr tmp, sizeof(tmp))
            copyMem(addr src6.sin6_addr, addr ip.address_v6, 16)
          of DST_IP: # temporary ignore destination ip address
            step = SRC_PORT
          of SRC_PORT:
            step = DST_PORT
            src6.sin6_port = htons(parseInt($cast[cstring](addr tmp)).uint16)
            zeroMem(addr tmp, sizeof(tmp))
            copyMem(sa, addr src6, sl[])
            return backslash_r
          of DST_PORT: # temporary ignore destination port
            break
          idx = 0
        else:
          tmp[idx] = c
          inc(idx)
    else: # not supported protocol
      return -1
  else: #  Wrong protocol
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
        echo "[PROXY] connection 0x", $result.int, " invalid proxy-protocol header"
        result = SocketHandle(-1)

  let accept_ptr = symAddr(RTLD_NEXT, "accept")
  if accept_ptr == nil:
    quit "[PROXY] cannot find accept proc"

  real_accept = cast[AcceptProc](accept_ptr)
  echo "[PROXY] hook accept OK"