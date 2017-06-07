let identity_tcp () =
  Crowbar.add_test ~name:"deserialize/serialize"
  Crowbar.[Generators.tcp_packet; Generators.ipv4_packet] @@ fun tcp ipv4 ->
  let payload = Cstruct.create 0 in
  let tcp_hlen = Tcp.Options.lenv tcp.options in
  let pseudoheader = Ipv4_packet.Marshal.pseudoheader
    ~src:ipv4.src ~dst:ipv4.dst ~proto:`TCP
    (tcp_hlen + Tcp.Tcp_wire.sizeof_tcp + Cstruct.len payload)
  in
  Crowbar.check_eq ~pp:Tcp.Tcp_packet.pp ~eq:Tcp.Tcp_packet.equal tcp
    (Tcp.Tcp_packet.Marshal.make_cstruct ~pseudoheader ~payload tcp |>
     Tcp.Tcp_packet.Unmarshal.of_cstruct |>
     function | Error _ -> Crowbar.bad_test () | Ok (n, _p) -> n)

let () = identity_tcp ()
