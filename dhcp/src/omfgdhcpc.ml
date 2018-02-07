(* what's the expected behavior of this program?
 * most important is that it doesn't crash...
 * definitely that a completed lease transaction returns a lease with the desired options
 * that no completed lease is reported without a DHCPACK?
 * that the discovering_client is never silent for more than x seconds regardless of the state?
 * that "no more work" is only the result of a discovering_client that has a lease? this might be a winner.  nope, because we return `None` in a *lot* of cases where we don't need to send the last message again. *)
(* the state machine should only advance if the xid matches *)

let really_parse buf =
  match Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) with
  | Error _ -> Crowbar.bad_test ()
  | Ok t -> t

let discovering_client : (Dhcp_client.t * Cstruct.t) Crowbar.gen =
  Crowbar.map Crowbar.[Generators.macaddr; list1 Generators.opt_code] (fun m o ->
  Dhcp_client.create ~requests:o m)

let range_server : Dhcp_server.Config.t Crowbar.gen =
  Crowbar.map Crowbar.[Generators.macaddr; Generators.ipv4_prefix] (fun m network ->
    Crowbar.guard (Ipaddr.V4.Prefix.bits network < 30);
      (* need room for our ip + at least one in the range *)
    let ip = Ipaddr.V4.Prefix.network network in
    let range_low = Ipaddr.V4.(of_int32 @@ Int32.add 1l @@ to_int32 ip) in
    let range_high = Ipaddr.V4.(of_int32 @@ Int32.sub (to_int32 @@ Prefix.broadcast network) 1l) in
      Dhcp_server.Config.make ?hostname:None ?default_lease_time:None
      ?max_lease_time:None ?hosts:None ~addr_tuple:(ip, m) ~network
         ~range:(Some (range_low, range_high)) ~options:[]
  )

let discovering_clients_are_fresh () =
  Crowbar.add_test ~name:"no lease on fresh discovering_client" Crowbar.[discovering_client] @@ fun (c, _buf) ->
  Crowbar.check (match Dhcp_client.lease c with | Some _ -> false | None -> true)

let discovering_clients_ask_for_opt_code () =
  Crowbar.add_test ~name:"discovering_clients ask for the given option codes"
    Crowbar.[Generators.macaddr; list1 Generators.opt_code] @@ fun m o ->
  let (_c, b) = Dhcp_client.create ~requests:o m in
  let b = really_parse b in
  Crowbar.check_eq Dhcp_wire.(find_parameter_requests b.options) (Some o)

let record_is_serializable () =
  Crowbar.add_test ~name:"record is serializable" Crowbar.[Generators.packet ()]
  @@ fun pkt -> ignore (Dhcp_wire.buf_of_pkt pkt); Crowbar.check true

let serialize_deserialize () =
  let pp fmt pkt =
    Format.fprintf fmt "%s" @@ Dhcp_wire.pkt_to_string pkt
  in
  Crowbar.add_test ~name:"records print/parse and are the same"
  Crowbar.[Generators.packet ()] @@ fun pkt ->
  let serialized = Dhcp_wire.buf_of_pkt pkt in
    let deserialized = really_parse serialized in
    Crowbar.check_eq ~pp ~cmp:(fun a b ->
      String.compare (Dhcp_wire.pkt_to_string a) (Dhcp_wire.pkt_to_string b)
    ) pkt deserialized

let xid_mismatch_always_noop () =
  Crowbar.add_test ~name:"input for other xids never gets a response"
    Crowbar.[discovering_client; Generators.packet ~with_msgtype:Dhcp_wire.DHCPOFFER ()] @@
    fun (discovering_client, dhcpdiscover) response ->
      let d = (really_parse dhcpdiscover) in
      Crowbar.guard Dhcp_wire.(d.xid <> response.xid); (* no fun to make them equal if they already are *)
      let coerced = Dhcp_wire.{response with xid = d.xid } in
      let coerced_response = Dhcp_wire.buf_of_pkt coerced in
      let uneq_action = Dhcp_client.input discovering_client (Dhcp_wire.buf_of_pkt response) in
      let coerced_action = Dhcp_client.input discovering_client coerced_response in
      Crowbar.guard (coerced_action <> `Noop);
      Crowbar.check_eq uneq_action `Noop

let one_message_no_lease () =
  Crowbar.add_test ~name:"one message doesn't get a lease"
  Crowbar.[discovering_client; Generators.packet ~with_msgtype:Dhcp_wire.DHCPACK ()] @@
  fun (discovering_client, _buf) message ->
  match Dhcp_client.input discovering_client (Dhcp_wire.buf_of_pkt message) with
  | `Noop -> Crowbar.bad_test ()
  | `Response _ -> Crowbar.check true
  | `New_lease _ -> Crowbar.check false

let client_intelligible_by_server () =
  Crowbar.add_test ~name:"fresh client and server can communicate without sharing config"
  Crowbar.[range_server; discovering_client] @@ fun s (_c, client_output) ->
     let open Dhcp_server in
     let dhcpdiscover = really_parse client_output in
     Crowbar.guard (Input.for_us s dhcpdiscover);
     match Input.input_pkt s (Lease.make_db ()) dhcpdiscover 0l with
     | Input.Silence | Input.Update _ -> Crowbar.check false
     | Input.Reply _ -> Crowbar.check true
     | Input.Warning s | Input.Error s ->
         (Printf.eprintf "something bad happened: %s\n%!" s; Crowbar.bad_test ())

let lease_in_four () =
  let open Dhcp_server in
  Crowbar.add_test ~name:"four message exchanges gets us a lease"
  Crowbar.[range_server; discovering_client] @@ fun s (c, send_me) ->
    let really_input s db buf time =
      match Input.input_pkt s db buf time with
      | Input.Silence | Input.Update _ | Input.Warning _ | Input.Error _ ->
        Crowbar.bad_test ()
      | Input.Reply (dhcpoffer, db) -> (dhcpoffer, db)
    in
    let err_no_response pkt =
      Crowbar.fail ("no response to " ^ Dhcp_wire.pkt_to_string pkt)
    in
    let time = 0l in
    let dhcpdiscover = really_parse send_me in
    let (dhcpoffer, db) = really_input s (Lease.make_db ()) dhcpdiscover time in
    match Dhcp_client.input c (Dhcp_wire.buf_of_pkt dhcpoffer) with
    | `Noop -> err_no_response dhcpoffer
    | `New_lease (_c, lease) ->
       Crowbar.fail ("client thought dhcpoffer gave it a lease " ^ Dhcp_wire.pkt_to_string lease)
    | `Response (c, dhcprequest) ->
      let dhcprequest = really_parse dhcprequest in
      let (dhcpack, _db) = really_input s db dhcprequest time in
      match Dhcp_client.input c (Dhcp_wire.buf_of_pkt dhcpack) with
      | `Noop -> err_no_response dhcpack
      | `Response (_c, wat) ->
         Crowbar.fail ("response to dhcpack: " ^ Dhcp_wire.pkt_to_string (really_parse wat))
      | `New_lease (c, l) -> Crowbar.check_eq (Dhcp_client.lease c) (Some l)

let () =
  discovering_clients_are_fresh ();
  record_is_serializable ();
  serialize_deserialize ();
  discovering_clients_ask_for_opt_code ();
  xid_mismatch_always_noop ();
  one_message_no_lease ();
  client_intelligible_by_server ();
  lease_in_four ();
