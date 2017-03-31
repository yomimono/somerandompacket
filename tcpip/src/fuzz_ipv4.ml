let main = Fuzz.main ~f:Ipv4_packet.Unmarshal.of_cstruct ~pp:Ipv4_packet.pp

let () = AflPersistent.run main
