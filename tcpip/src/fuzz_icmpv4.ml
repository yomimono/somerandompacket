let main = Fuzz.main ~f:Icmpv4_packet.Unmarshal.of_cstruct ~pp:Icmpv4_packet.pp

let () = AflPersistent.run main
