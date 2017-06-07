let () =
  Fuzz.identity_more
  ~pp:Ipv4_packet.pp ~eq:Ipv4_packet.equal
  ~serialize:(Ipv4_packet.Marshal.make_cstruct ~payload_len:0)
  ~deserialize:Ipv4_packet.Unmarshal.of_cstruct
  Generators.ipv4_packet
