let identity_udp () =
  Crowbar.add_test ~name:"deserialize/serialize"
  Crowbar.[Generators.udp_packet; Generators.ipv4_packet] @@ fun udp ipv4 ->
  let payload = Cstruct.create 0 in
  let pseudoheader = Ipv4_packet.Marshal.pseudoheader
    ~src:ipv4.src ~dst:ipv4.dst ~proto:`UDP
    (Udp_wire.sizeof_udp + Cstruct.len payload)
  in
  Crowbar.check_eq ~pp:Udp_packet.pp ~eq:Udp_packet.equal udp
    (Udp_packet.Marshal.make_cstruct ~pseudoheader ~payload udp |>
     Udp_packet.Unmarshal.of_cstruct |>
     function | Error _ -> Crowbar.bad_test () | Ok (n, _p) -> n)

let () = identity_udp ()
