let () =
  Fuzz.identity
       ~pp:Arpv4_packet.pp
       ~serialize:Arpv4_packet.Marshal.make_cstruct
       ~deserialize:Arpv4_packet.Unmarshal.of_cstruct 
       Generators.arpv4_packet
