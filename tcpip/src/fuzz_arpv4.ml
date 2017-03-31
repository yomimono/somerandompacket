let main = Fuzz.main ~f:Arpv4_packet.Unmarshal.of_cstruct ~pp:Arpv4_packet.pp

let () = AflPersistent.run main
