open Crowbar
open Dhcp_wire

(* what's the expected behavior of this program?
 * most important is that it doesn't crash...
 * definitely that a completed lease transaction returns a lease with the desired options
 * that no completed lease is reported without a DHCPACK?
 * that the discovering_client is never silent for more than x seconds regardless of the state?
 * that "no more work" is only the result of a discovering_client that has a lease? this might be a winner.  nope, because we return `None` in a *lot* of cases where we don't need to send the last message again. *)
(* the state machine should only advance if the xid matches *)

let do_your_best f n =
  match f n with
  | None -> bad_test ()
  | Some a -> a

let really_parse buf =
  match pkt_of_buf buf (Cstruct.len buf) with
  | Error s -> Printf.eprintf "%s\n%!" s; bad_test ()
  | Ok t -> t

let macaddr : Macaddr.t gen =
  Map ([uint8; uint8; uint8; uint8; uint8; uint8], fun a b c d e f ->
    match Macaddr.of_string (Printf.sprintf "%02x:%02x:%02x:%02x:%02x:%02x" a b c d e f) with
    | Some m -> m
    | None -> bad_test ()
  )

let uint16 : Cstruct.uint16 gen =
  Map ([uint8; uint8], fun u l -> (u lsl 4) + l)

let ipv4 : Ipaddr.V4.t gen =
  Map ([int32], Ipaddr.V4.of_int32)

let ipv4_prefix : Ipaddr.V4.Prefix.t gen =
  Map ([range 31; ipv4], fun a b -> Ipaddr.V4.Prefix.make (a+1) b)

let static_routes : (Ipaddr.V4.t * Ipaddr.V4.t) gen =
  Map ([ipv4; ipv4], fun a b -> a, b)

let opt_code : option_code gen =
  Map ([uint8], do_your_best int_to_option_code)

let client_id : client_id gen =
  Choose [
    Map ([macaddr], fun a -> Hwaddr a);
    Map ([bytes], fun a-> Id a)
  ]

let msgtype : msgtype gen =
  Map ([range 14], fun a -> do_your_best int_to_msgtype (a+1))

let opt : dhcp_option gen =
  let open Dhcp_wire in
  Choose [
    Map ([ipv4], fun a -> Subnet_mask a);
    Map ([int32], fun a -> Time_offset a);
    Map ([List1 ipv4], fun a -> Routers a);
    Map ([List1 ipv4], fun a -> Time_servers a);
    Map ([List1 ipv4], fun a -> Name_servers a);
    Map ([List1 ipv4], fun a -> Dns_servers a);
    Map ([List1 ipv4], fun a -> Log_servers a);
    Map ([List1 ipv4], fun a -> Cookie_servers a);
    Map ([List1 ipv4], fun a -> Lpr_servers a);
    Map ([List1 ipv4], fun a -> Impress_servers a);
    Map ([List1 ipv4], fun a -> Rsclocation_servers a);
    Map ([bytes], fun a -> Hostname a);
    Map ([int], fun a -> Bootfile_size a);
    Map ([bytes], fun a -> Merit_dumpfile a);
    Map ([bytes], fun a -> Domain_name a);
    Map ([ipv4], fun a -> Swap_server a);
    Map ([bytes], fun a -> Root_path a);
    Map ([bytes], fun a -> Extension_path a);
    Map ([bool], fun a -> Ipforwarding a);
    Map ([bool], fun a -> Nlsr a);
    Map ([List1 ipv4_prefix], fun a -> Policy_filters a);
    Map ([int], fun a -> Max_datagram a);
    Map ([int], fun a -> Default_ip_ttl a);
    Map ([int], fun a -> Default_ip_ttl a);
    Map ([int32], fun a -> Pmtu_ageing_timo a);
    Map ([List1 int], fun a -> Pmtu_plateau_table a);
    Map ([int], fun a -> Interface_mtu a);
    Map ([bool], fun a -> All_subnets_local a);
    Map ([ipv4], fun a -> Broadcast_addr a);
    Map ([bool], fun a -> Perform_mask_discovery a);
    Map ([bool], fun a -> Mask_supplier a);
    Map ([bool], fun a -> Perform_router_disc a);
    Map ([ipv4], fun a -> Router_sol_addr a);
    Map ([List1 static_routes], fun a -> Static_routes a);
    Map ([bool], fun a -> Trailer_encapsulation a);
    Map ([int32], fun a -> Arp_cache_timo a);
    Map ([bool], fun a -> Ethernet_encapsulation a);
    Map ([int], fun a -> Tcp_default_ttl a);
    Map ([int32], fun a -> Tcp_keepalive_interval a);
    Map ([int], fun a -> Tcp_keepalive_garbage a);
    Map ([bytes], fun a -> Nis_domain a);
    Map ([List1 ipv4], fun a -> Nis_servers a);
    Map ([List1 ipv4], fun a -> Ntp_servers a);
    Map ([bytes], fun a -> Vendor_specific a);
    Map ([List1 ipv4], fun a -> Netbios_name_servers a);
    Map ([List1 ipv4], fun a -> Netbios_datagram_distrib_servers a);
    Map ([int], fun a -> Netbios_node a);
    Map ([bytes], fun a -> Netbios_scope a);
    Map ([List1 ipv4], fun a -> Xwindow_font_servers a);
    Map ([List1 ipv4], fun a -> Xwindow_display_managers a);
    Map ([ipv4], fun a -> Request_ip a);
    Map ([int32], fun a -> Ip_lease_time a);
    Map ([int], fun a -> Option_overload a);
    Map ([msgtype], fun a -> Message_type a);
    Map ([ipv4], fun a -> Server_identifier a);
    Map ([List1 opt_code], fun a -> Parameter_requests a);
    Map ([bytes], fun a -> Message a);
    Map ([int], fun a -> Max_message a);
    Map ([int32], fun a -> Renewal_t1 a);
    Map ([int32], fun a -> Rebinding_t2 a);
    Map ([bytes], fun a -> Vendor_class_id a);
    Map ([client_id], fun a -> Client_id a);
    Map ([bytes], fun a -> Netware_ip_domain a);
    Map ([bytes], fun a -> Netware_ip_option a);
    Map ([bytes], fun a -> Nis_plus_domain a);
    Map ([List1 ipv4], fun a -> Nis_plus_servers a);
    Map ([bytes], fun a -> Tftp_server_name a);
    Map ([bytes], fun a -> Bootfile_name a);
    Map ([List ipv4], fun a -> Mobile_ip_home_agent a);
    Map ([List1 ipv4], fun a -> Smtp_servers a);
    Map ([List1 ipv4], fun a -> Pop3_servers a);
    Map ([List1 ipv4], fun a -> Nntp_servers a);
    Map ([List1 ipv4], fun a -> Www_servers a);
    Map ([List1 ipv4], fun a -> Finger_servers a);
    Map ([List1 ipv4], fun a -> Irc_servers a);
    Map ([List1 ipv4], fun a -> Streettalk_servers a);
    Map ([List1 ipv4], fun a -> Streettalk_da a);
    Map ([bytes], fun a -> User_class a);
    Map ([bytes], fun a -> Directory_agent a);
    Map ([bytes], fun a -> Service_scope a);
    Const Rapid_commit;
    Map ([bytes], fun a -> Client_fqdn a);
    Map ([bytes], fun a -> Relay_agent_information a);
    Map ([bytes], fun a -> Isns a);
    Map ([bytes], fun a -> Nds_servers a);
    Map ([bytes], fun a -> Nds_tree_name a);
    Map ([bytes], fun a -> Nds_context a);
    Map ([bytes], fun a -> Bcmcs_controller_domain_name_list a);
    Map ([List1 ipv4], fun a -> Bcmcs_controller_ipv4_addrs a);
    Map ([bytes], fun a -> Authentication a);
    Map ([int32], fun a -> Client_last_transaction_time a);
    Map ([List1 ipv4], fun a -> Associated_ips a);
    Map ([bytes], fun a -> Client_system a);
    Map ([bytes], fun a -> Client_ndi a);
    Map ([bytes], fun a -> Ldap a);
    Map ([bytes], fun a -> Uuid_guid a);
    Map ([bytes], fun a -> User_auth a);
    Map ([bytes], fun a -> Geoconf_civic a);
    Map ([bytes], fun a -> Pcode a);
    Map ([bytes], fun a -> Tcode a);
    Map ([bytes], fun a -> Netinfo_address a);
    Map ([bytes], fun a -> Netinfo_tag a);
    Map ([bytes], fun a -> Url a);
    Map ([int], fun a -> Auto_config a);
    Map ([bytes], fun a -> Name_service_search a);
    Map ([ipv4], fun a -> Subnet_selection a);
    Map ([bytes], fun a -> Domain_search a);
    Map ([bytes], fun a -> Sip_servers a);
    Map ([bytes], fun a -> Classless_static_route a);
    Map ([bytes], fun a -> Ccc a);
    Map ([bytes], fun a -> Geoconf a);
    Map ([bytes], fun a -> Vi_vendor_class a);
    Map ([bytes], fun a -> Vi_vendor_info a);
    Map ([bytes], fun a -> Pxe_128 a);
    Map ([bytes], fun a -> Pxe_129 a);
    Map ([bytes], fun a -> Pxe_130 a);
    Map ([bytes], fun a -> Pxe_131 a);
    Map ([bytes], fun a -> Pxe_132 a);
    Map ([bytes], fun a -> Pxe_133 a);
    Map ([bytes], fun a -> Pxe_134 a);
    Map ([bytes], fun a -> Pxe_135 a);
    Map ([bytes], fun a -> Pana_agent a);
    Map ([bytes], fun a -> V4_lost a);
    Map ([bytes], fun a -> Capwap_ac_v4 a);
    Map ([bytes], fun a -> Ipv4_address_mos a);
    Map ([bytes], fun a -> Ipv4_fqdn_mos a);
    Map ([bytes], fun a -> Sip_ua_domains a);
    Map ([bytes], fun a -> Ipv4_address_andsf a);
    Map ([bytes], fun a -> Geolock a);
    Map ([bytes], fun a -> Forcenew_nonce_capable a);
    Map ([bytes], fun a -> Rdnss_selection a);
    Map ([bytes], fun a -> Misc_150 a);
    Map ([bytes], fun a -> Status_code a);
    Map ([int32], fun a -> Absolute_time a);
    Map ([int32], fun a -> Start_time_of_state a);
    Map ([int32], fun a -> Query_start_time a);
    Map ([int32], fun a -> Query_end_time a);
    Map ([int], fun a -> Dhcp_state a);
    Map ([int], fun a -> Data_source a);
    Map ([bytes], fun a -> V4_pcp_server a);
    Map ([bytes], fun a -> V4_portparams a);
    Map ([bytes], fun a -> Dhcp_captive_portal a);
    Map ([bytes], fun a -> Etherboot_175 a);
    Map ([bytes], fun a -> Ip_telefone a);
    Map ([bytes], fun a -> Etherboot_177 a);
    Map ([int32], fun a -> Pxe_linux a);
    Map ([bytes], fun a -> Configuration_file a);
    Map ([bytes], fun a -> Path_prefix a);
    Map ([int32], fun a -> Reboot_time a);
    Map ([bytes], fun a -> Option_6rd a);
    Map ([bytes], fun a -> V4_access_domain a);
    Map ([int], fun a -> Subnet_allocation a);
    Map ([bytes], fun a -> Virtual_subnet_selection a);
    Map ([bytes], fun a -> Web_proxy_auto_disc a);
    Const End;
    Map ([opt_code; bytes], fun a b -> Unassigned (a, b));
  ]

let op : op gen =
  Map ([range 1], fun n -> int_to_op_exn @@ n+1)

let htype : htype gen = Const Dhcp_wire.Ethernet_10mb
let hlen = Const 6

let flags : flags gen = 
  Map ([range 1], function | 0 -> Broadcast | _n -> Dhcp_wire.Unicast)

let packet ?with_msgtype () : pkt gen =
  let msg_gen = match with_msgtype with
  | Some m -> Const m
  | None -> msgtype
  in
    Map ([
      macaddr; macaddr;
      ipv4; ipv4;
      uint16; uint16;
      op;
      htype; hlen;
      uint16;
      int32;
      int;
      flags;
      ipv4; ipv4; ipv4; ipv4;
      macaddr;
      bytes; bytes;
      msg_gen;
      List1 opt;
    ], fun srcmac dstmac srcip dstip srcport dstport op htype hlen hops xid secs
           flags ciaddr yiaddr siaddr giaddr chaddr sname file msg opt ->
           { srcmac = srcmac; dstmac; srcip; dstip; srcport; dstport;
             op; htype; hlen; hops; xid; secs; flags;
             ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
             options = (Message_type msg) :: opt; }
    )

let discovering_client : (Dhcp_client.t * Cstruct.t) gen =
  Map ([macaddr; List1 opt_code], fun m o ->
  Dhcp_client.create ~requests:o m)

let range_server : Dhcp_server.Config.t gen =
  Map ([macaddr; ipv4_prefix], fun m network ->
    guard (Ipaddr.V4.Prefix.bits network < 30);
      (* need room for our ip + at least one in the range *)
    let ip = Ipaddr.V4.Prefix.network network in
    let range_low = Ipaddr.V4.(of_int32 @@ Int32.add 1l @@ to_int32 ip) in
    let range_high = Ipaddr.V4.(of_int32 @@ Int32.sub (to_int32 @@ Prefix.broadcast network) 1l) in
      Dhcp_server.Config.make ?hostname:None ?default_lease_time:None 
      ?max_lease_time:None ?hosts:None ~addr_tuple:(ip, m) ~network
         ~range:(Some (range_low, range_high)) ~options:[]
  )

let discovering_clients_are_fresh () =
  add_test ~name:"no lease on fresh discovering_client" [discovering_client] @@ fun (c, _buf) ->
  check (match Dhcp_client.lease c with | Some _ -> false | None -> true)

let discovering_clients_ask_for_opt_code () =
  add_test ~name:"discovering_clients ask for the given option codes" [macaddr; List1 opt_code] @@ fun m o ->
  let (_c, b) = Dhcp_client.create ~requests:o m in
  let b = really_parse b in
  check_eq (find_parameter_requests b.options) (Some o)

let record_is_serializable () =
  add_test ~name:"record is serializable" [packet ()] @@ fun pkt ->
  ignore (buf_of_pkt pkt); check true

let serialize_deserialize () =
  let pp fmt pkt =
    Format.fprintf fmt "%s" @@ pkt_to_string pkt
  in
  add_test ~name:"records print/parse and are the same" [packet ()] @@ fun pkt ->
  let serialized = buf_of_pkt pkt in
    let deserialized =
      pkt_of_buf serialized (Cstruct.len serialized) |> Rresult.R.get_ok
    in
    check_eq ~pp ~cmp:(fun a b -> String.compare (pkt_to_string a) (Dhcp_wire.pkt_to_string b))
    pkt deserialized

let xid_mismatch_always_noop () =
  add_test ~name:"input for other xids never gets a response"
    [discovering_client; packet ~with_msgtype:DHCPOFFER ()] @@ fun (discovering_client, dhcpdiscover) response ->
      let d = (really_parse dhcpdiscover) in
      guard (d.xid <> response.xid); (* no fun to make them equal if they already are *)
      let coerced = {response with xid = d.xid } in
      let coerced_response = buf_of_pkt coerced in
      let uneq_action = Dhcp_client.input discovering_client (buf_of_pkt response) in
      let coerced_action = Dhcp_client.input discovering_client coerced_response in
      guard (coerced_action <> `Noop);
      check_eq uneq_action `Noop

let one_message_no_lease () =
  add_test ~name:"one message doesn't get a lease" [discovering_client; packet ~with_msgtype:DHCPACK ()] @@ fun (discovering_client, _buf) message ->
  match Dhcp_client.input discovering_client (buf_of_pkt message) with
  | `Response _ | `Noop -> check true
  | `New_lease _ -> check false

let client_intelligible_by_server () =
  add_test ~name:"fresh client and server can communicate without sharing config"
  [range_server; discovering_client] @@ fun s (_c, client_output) ->
     let open Dhcp_server in
     let dhcpdiscover = really_parse client_output in
     guard (Input.for_us s dhcpdiscover);
     match Input.input_pkt s (Lease.make_db ()) dhcpdiscover 0l with
     | Input.Silence | Input.Update _ -> check false
     | Input.Reply _ -> check true
     | Input.Warning s | Input.Error s ->
         (Printf.eprintf "something bad happened: %s\n%!" s; bad_test ())

let lease_in_four () =
  let open Dhcp_server in
  add_test ~name:"four message exchanges gets us a lease"
  [range_server; discovering_client] @@ fun s (c, send_me) ->
    let really_input s db buf time =
      match Input.input_pkt s db buf time with
      | Input.Silence | Input.Update _ | Input.Warning _ | Input.Error _ -> bad_test ()
      | Input.Reply (dhcpoffer, db) -> (dhcpoffer, db)
    in
    let err_no_response pkt = 
      Error (fun ppf () -> pp ppf "no response to %s" @@ pkt_to_string pkt)
    in
    let time = 0l in
    let dhcpdiscover = really_parse send_me in
    let (dhcpoffer, db) = really_input s (Lease.make_db ()) dhcpdiscover time in
    match Dhcp_client.input c (buf_of_pkt dhcpoffer) with
    | `Noop -> err_no_response dhcpoffer
    | `New_lease (_c, lease) ->
      Error (fun ppf () -> pp ppf "client thought dhcpoffer gave it a lease %s" @@ pkt_to_string lease)
    | `Response (c, dhcprequest) ->
      let dhcprequest = really_parse dhcprequest in
      let (dhcpack, _db) = really_input s db dhcprequest time in
      match Dhcp_client.input c (buf_of_pkt dhcpack) with
      | `Noop -> err_no_response dhcpack
      | `Response (_c, wat) ->
        Error (fun ppf () -> pp ppf "response to dhcpack: %s" @@ pkt_to_string (really_parse wat))
      | `New_lease (c, l) -> check_eq (Dhcp_client.lease c) (Some l)

let () =
  discovering_clients_are_fresh ();
  record_is_serializable ();
  discovering_clients_ask_for_opt_code ();
  xid_mismatch_always_noop ();
  one_message_no_lease ();
  client_intelligible_by_server ();
  lease_in_four ();
