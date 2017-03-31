let main = Fuzz.main ~f:Udp_packet.Unmarshal.of_cstruct ~pp:Udp_packet.pp

let () = AflPersistent.run main
