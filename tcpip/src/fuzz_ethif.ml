let () =
  Fuzz.identity_more
  ~pp:Ethif_packet.pp
  ~serialize:Ethif_packet.Marshal.make_cstruct
  ~deserialize:Ethif_packet.Unmarshal.of_cstruct
  Generators.ethif_packet
