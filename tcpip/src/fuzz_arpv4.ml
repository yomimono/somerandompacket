let deserialize () =
  Crowbar.add_test ~name:"packets are serializable" Crowbar.[Generators.arpv4_packet] @@ fun t ->
  Crowbar.check true

let () =
  deserialize ();
