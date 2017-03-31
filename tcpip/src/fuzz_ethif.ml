let main = Fuzz.main ~f:Ethif_packet.Unmarshal.of_cstruct ~pp:Ethif_packet.pp

let () = AflPersistent.run main
