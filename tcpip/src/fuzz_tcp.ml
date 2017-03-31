let main = Fuzz.main ~f:Tcp.Tcp_packet.Unmarshal.of_cstruct ~pp:Tcp.Tcp_packet.pp

let () = AflPersistent.run main
