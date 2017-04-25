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
  | None -> Crowbar.bad_test ()
  | Some a -> a

let really_parse buf =
  match pkt_of_buf buf (Cstruct.len buf) with
  | Error _ -> Crowbar.bad_test ()
  | Ok t -> t

let macaddr : Macaddr.t Crowbar.gen =
  Crowbar.Map ([uint8; uint8; uint8; uint8; uint8; uint8], fun a b c d e f ->
  Macaddr.make_local @@ function
    | 0 -> (a lsl 2)
    | 1 -> b | 2 -> c | 3 -> d | 4 -> e | _n -> f
  )

let uint16 : Cstruct.uint16 Crowbar.gen =
  Crowbar.Map ([uint8; uint8], fun u l -> (u lsl 4) + l)

let ipv4 : Ipaddr.V4.t Crowbar.gen =
  Crowbar.Map ([int32], Ipaddr.V4.of_int32)

let ipv4_prefix : Ipaddr.V4.Prefix.t Crowbar.gen =
  Crowbar.Map ([range 31; ipv4], fun a b -> Ipaddr.V4.Prefix.make (a+1) b)

let static_routes : (Ipaddr.V4.t * Ipaddr.V4.t) Crowbar.gen =
  Crowbar.Map ([ipv4; ipv4], fun a b -> a, b)

let opt_code : option_code Crowbar.gen =
  Crowbar.Map ([uint8], do_your_best int_to_option_code)

let unassigned_code : option_code Crowbar.gen =
 Crowbar.Choose [
    Crowbar.Const UNASSIGNED_84;
    Crowbar.Const UNASSIGNED_96;
    Crowbar.Const UNASSIGNED_102;
    Crowbar.Const UNASSIGNED_103;
    Crowbar.Const UNASSIGNED_104;
    Crowbar.Const UNASSIGNED_105;
    Crowbar.Const UNASSIGNED_106;
    Crowbar.Const UNASSIGNED_107;
    Crowbar.Const UNASSIGNED_108;
    Crowbar.Const UNASSIGNED_109;
    Crowbar.Const UNASSIGNED_110;
    Crowbar.Const UNASSIGNED_111;
    Crowbar.Const UNASSIGNED_115;
    Crowbar.Const UNASSIGNED_126;
    Crowbar.Const UNASSIGNED_127;
    Crowbar.Const UNASSIGNED_143;
    Crowbar.Const UNASSIGNED_147;
    Crowbar.Const UNASSIGNED_148;
    Crowbar.Const UNASSIGNED_149;
    Crowbar.Const UNASSIGNED_161;
    Crowbar.Const UNASSIGNED_162;
    Crowbar.Const UNASSIGNED_163;
    Crowbar.Const UNASSIGNED_164;
    Crowbar.Const UNASSIGNED_165;
    Crowbar.Const UNASSIGNED_166;
    Crowbar.Const UNASSIGNED_167;
    Crowbar.Const UNASSIGNED_168;
    Crowbar.Const UNASSIGNED_169;
    Crowbar.Const UNASSIGNED_170;
    Crowbar.Const UNASSIGNED_171;
    Crowbar.Const UNASSIGNED_172;
    Crowbar.Const UNASSIGNED_173;
    Crowbar.Const UNASSIGNED_174;
    Crowbar.Const UNASSIGNED_178;
    Crowbar.Const UNASSIGNED_179;
    Crowbar.Const UNASSIGNED_180;
    Crowbar.Const UNASSIGNED_181;
    Crowbar.Const UNASSIGNED_182;
    Crowbar.Const UNASSIGNED_183;
    Crowbar.Const UNASSIGNED_184;
    Crowbar.Const UNASSIGNED_185;
    Crowbar.Const UNASSIGNED_186;
    Crowbar.Const UNASSIGNED_187;
    Crowbar.Const UNASSIGNED_188;
    Crowbar.Const UNASSIGNED_189;
    Crowbar.Const UNASSIGNED_190;
    Crowbar.Const UNASSIGNED_191;
    Crowbar.Const UNASSIGNED_192;
    Crowbar.Const UNASSIGNED_193;
    Crowbar.Const UNASSIGNED_194;
    Crowbar.Const UNASSIGNED_195;
    Crowbar.Const UNASSIGNED_196;
    Crowbar.Const UNASSIGNED_197;
    Crowbar.Const UNASSIGNED_198;
    Crowbar.Const UNASSIGNED_199;
    Crowbar.Const UNASSIGNED_200;
    Crowbar.Const UNASSIGNED_201;
    Crowbar.Const UNASSIGNED_202;
    Crowbar.Const UNASSIGNED_203;
    Crowbar.Const UNASSIGNED_204;
    Crowbar.Const UNASSIGNED_205;
    Crowbar.Const UNASSIGNED_206;
    Crowbar.Const UNASSIGNED_207;
    Crowbar.Const UNASSIGNED_214;
    Crowbar.Const UNASSIGNED_215;
    Crowbar.Const UNASSIGNED_216;
    Crowbar.Const UNASSIGNED_217;
    Crowbar.Const UNASSIGNED_218;
    Crowbar.Const UNASSIGNED_219;
    Crowbar.Const UNASSIGNED_222;
    Crowbar.Const UNASSIGNED_223;
  ]

let unassigned : dhcp_option Crowbar.gen =
  Crowbar.Map ([unassigned_code; bytes], fun a s ->
  Unassigned (a, s)
)

let client_id : client_id Crowbar.gen =
  Crowbar.Choose [
    Crowbar.Map ([macaddr], fun a -> Hwaddr a);
    Crowbar.Map ([bytes], fun a-> Id a)
  ]

let msgtype : msgtype Crowbar.gen =
  Crowbar.Map ([range 14], fun a -> do_your_best int_to_msgtype (a+1))

let opt : dhcp_option Crowbar.gen =
  let open Dhcp_wire in
 Crowbar.Choose [
    Crowbar.Map ([ipv4], fun a -> Subnet_mask a);
    Crowbar.Map ([int32], fun a -> Time_offset a);
    Crowbar.Map ([List1 ipv4], fun a -> Routers a);
    Crowbar.Map ([List1 ipv4], fun a -> Time_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Name_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Dns_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Log_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Cookie_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Lpr_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Impress_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Rsclocation_servers a);
    Crowbar.Map ([bytes], fun a -> Hostname a);
    Crowbar.Map ([uint16], fun a -> Bootfile_size a);
    Crowbar.Map ([bytes], fun a -> Merit_dumpfile a);
    Crowbar.Map ([bytes], fun a -> Domain_name a);
    Crowbar.Map ([ipv4], fun a -> Swap_server a);
    Crowbar.Map ([bytes], fun a -> Root_path a);
    Crowbar.Map ([bytes], fun a -> Extension_path a);
    Crowbar.Map ([bool], fun a -> Ipforwarding a);
    Crowbar.Map ([bool], fun a -> Nlsr a);
    Crowbar.Map ([List1 ipv4_prefix], fun a -> Policy_filters a);
    Crowbar.Map ([uint16], fun a -> Max_datagram a);
    Crowbar.Map ([uint8], fun a -> Default_ip_ttl a);
    Crowbar.Map ([int32], fun a -> Pmtu_ageing_timo a);
    Crowbar.Map ([List1 uint16], fun a -> Pmtu_plateau_table a);
    Crowbar.Map ([uint16], fun a -> Interface_mtu a);
    Crowbar.Map ([bool], fun a -> All_subnets_local a);
    Crowbar.Map ([ipv4], fun a -> Broadcast_addr a);
    Crowbar.Map ([bool], fun a -> Perform_mask_discovery a);
    Crowbar.Map ([bool], fun a -> Mask_supplier a);
    Crowbar.Map ([bool], fun a -> Perform_router_disc a);
    Crowbar.Map ([ipv4], fun a -> Router_sol_addr a);
    Crowbar.Map ([List1 static_routes], fun a -> Static_routes a);
    Crowbar.Map ([bool], fun a -> Trailer_encapsulation a);
    Crowbar.Map ([int32], fun a -> Arp_cache_timo a);
    Crowbar.Map ([bool], fun a -> Ethernet_encapsulation a);
    Crowbar.Map ([uint8], fun a -> Tcp_default_ttl a);
    Crowbar.Map ([int32], fun a -> Tcp_keepalive_interval a);
    Crowbar.Map ([uint8], fun a -> Tcp_keepalive_garbage a);
    Crowbar.Map ([bytes], fun a -> Nis_domain a);
    Crowbar.Map ([List1 ipv4], fun a -> Nis_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Ntp_servers a);
    Crowbar.Map ([bytes], fun a -> Vendor_specific a);
    Crowbar.Map ([List1 ipv4], fun a -> Netbios_name_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Netbios_datagram_distrib_servers a);
    Crowbar.Map ([uint8], fun a -> Netbios_node a);
    Crowbar.Map ([bytes], fun a -> Netbios_scope a);
    Crowbar.Map ([List1 ipv4], fun a -> Xwindow_font_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Xwindow_display_managers a);
    Crowbar.Map ([ipv4], fun a -> Request_ip a);
    Crowbar.Map ([int32], fun a -> Ip_lease_time a);
    Crowbar.Map ([uint8], fun a -> Option_overload a);
    Crowbar.Map ([msgtype], fun a -> Message_type a);
    Crowbar.Map ([ipv4], fun a -> Server_identifier a);
    Crowbar.Map ([List1 opt_code], fun a -> Parameter_requests a);
    Crowbar.Map ([bytes], fun a -> Message a);
    Crowbar.Map ([uint16], fun a -> Max_message a);
    Crowbar.Map ([int32], fun a -> Renewal_t1 a);
    Crowbar.Map ([int32], fun a -> Rebinding_t2 a);
    Crowbar.Map ([bytes], fun a -> Vendor_class_id a);
    Crowbar.Map ([client_id], fun a -> Client_id a);
    Crowbar.Map ([bytes], fun a -> Netware_ip_domain a);
    Crowbar.Map ([bytes], fun a -> Netware_ip_option a);
    Crowbar.Map ([bytes], fun a -> Nis_plus_domain a);
    Crowbar.Map ([List1 ipv4], fun a -> Nis_plus_servers a);
    Crowbar.Map ([bytes], fun a -> Tftp_server_name a);
    Crowbar.Map ([bytes], fun a -> Bootfile_name a);
    Crowbar.Map ([List ipv4], fun a -> Mobile_ip_home_agent a);
    Crowbar.Map ([List1 ipv4], fun a -> Smtp_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Pop3_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Nntp_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Www_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Finger_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Irc_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Streettalk_servers a);
    Crowbar.Map ([List1 ipv4], fun a -> Streettalk_da a);
    Crowbar.Map ([bytes], fun a -> User_class a);
    Crowbar.Map ([bytes], fun a -> Directory_agent a);
    Crowbar.Map ([bytes], fun a -> Service_scope a);
    Crowbar.Const Rapid_commit;
    Crowbar.Map ([bytes], fun a -> Client_fqdn a);
    Crowbar.Map ([bytes], fun a -> Relay_agent_information a);
    Crowbar.Map ([bytes], fun a -> Isns a);
    Crowbar.Map ([bytes], fun a -> Nds_servers a);
    Crowbar.Map ([bytes], fun a -> Nds_tree_name a);
    Crowbar.Map ([bytes], fun a -> Nds_context a);
    Crowbar.Map ([bytes], fun a -> Bcmcs_controller_domain_name_list a);
    Crowbar.Map ([List1 ipv4], fun a -> Bcmcs_controller_ipv4_addrs a);
    Crowbar.Map ([bytes], fun a -> Authentication a);
    Crowbar.Map ([int32], fun a -> Client_last_transaction_time a);
    Crowbar.Map ([List1 ipv4], fun a -> Associated_ips a);
    Crowbar.Map ([bytes], fun a -> Client_system a);
    Crowbar.Map ([bytes], fun a -> Client_ndi a);
    Crowbar.Map ([bytes], fun a -> Ldap a);
    Crowbar.Map ([bytes], fun a -> Uuid_guid a);
    Crowbar.Map ([bytes], fun a -> User_auth a);
    Crowbar.Map ([bytes], fun a -> Geoconf_civic a);
    Crowbar.Map ([bytes], fun a -> Pcode a);
    Crowbar.Map ([bytes], fun a -> Tcode a);
    Crowbar.Map ([bytes], fun a -> Netinfo_address a);
    Crowbar.Map ([bytes], fun a -> Netinfo_tag a);
    Crowbar.Map ([bytes], fun a -> Url a);
    Crowbar.Map ([uint8], fun a -> Auto_config a);
    Crowbar.Map ([bytes], fun a -> Name_service_search a);
    Crowbar.Map ([ipv4], fun a -> Subnet_selection a);
    Crowbar.Map ([bytes], fun a -> Domain_search a);
    Crowbar.Map ([bytes], fun a -> Sip_servers a);
    Crowbar.Map ([bytes], fun a -> Classless_static_route a);
    Crowbar.Map ([bytes], fun a -> Ccc a);
    Crowbar.Map ([bytes], fun a -> Geoconf a);
    Crowbar.Map ([bytes], fun a -> Vi_vendor_class a);
    Crowbar.Map ([bytes], fun a -> Vi_vendor_info a);
    Crowbar.Map ([bytes], fun a -> Pxe_128 a);
    Crowbar.Map ([bytes], fun a -> Pxe_129 a);
    Crowbar.Map ([bytes], fun a -> Pxe_130 a);
    Crowbar.Map ([bytes], fun a -> Pxe_131 a);
    Crowbar.Map ([bytes], fun a -> Pxe_132 a);
    Crowbar.Map ([bytes], fun a -> Pxe_133 a);
    Crowbar.Map ([bytes], fun a -> Pxe_134 a);
    Crowbar.Map ([bytes], fun a -> Pxe_135 a);
    Crowbar.Map ([bytes], fun a -> Pana_agent a);
    Crowbar.Map ([bytes], fun a -> V4_lost a);
    Crowbar.Map ([bytes], fun a -> Capwap_ac_v4 a);
    Crowbar.Map ([bytes], fun a -> Ipv4_address_mos a);
    Crowbar.Map ([bytes], fun a -> Ipv4_fqdn_mos a);
    Crowbar.Map ([bytes], fun a -> Sip_ua_domains a);
    Crowbar.Map ([bytes], fun a -> Ipv4_address_andsf a);
    Crowbar.Map ([bytes], fun a -> Geolock a);
    Crowbar.Map ([bytes], fun a -> Forcenew_nonce_capable a);
    Crowbar.Map ([bytes], fun a -> Rdnss_selection a);
    Crowbar.Map ([bytes], fun a -> Misc_150 a);
    Crowbar.Map ([bytes], fun a -> Status_code a);
    Crowbar.Map ([int32], fun a -> Absolute_time a);
    Crowbar.Map ([int32], fun a -> Start_time_of_state a);
    Crowbar.Map ([int32], fun a -> Query_start_time a);
    Crowbar.Map ([int32], fun a -> Query_end_time a);
    Crowbar.Map ([uint8], fun a -> Dhcp_state a);
    Crowbar.Map ([uint8], fun a -> Data_source a);
    Crowbar.Map ([bytes], fun a -> V4_pcp_server a);
    Crowbar.Map ([bytes], fun a -> V4_portparams a);
    Crowbar.Map ([bytes], fun a -> Dhcp_captive_portal a);
    Crowbar.Map ([bytes], fun a -> Etherboot_175 a);
    Crowbar.Map ([bytes], fun a -> Ip_telefone a);
    Crowbar.Map ([bytes], fun a -> Etherboot_177 a);
    Crowbar.Map ([int32], fun a -> Pxe_linux a);
    Crowbar.Map ([bytes], fun a -> Configuration_file a);
    Crowbar.Map ([bytes], fun a -> Path_prefix a);
    Crowbar.Map ([int32], fun a -> Reboot_time a);
    Crowbar.Map ([bytes], fun a -> Option_6rd a);
    Crowbar.Map ([bytes], fun a -> V4_access_domain a);
    Crowbar.Map ([uint8], fun a -> Subnet_allocation a);
    Crowbar.Map ([bytes], fun a -> Virtual_subnet_selection a);
    Crowbar.Map ([bytes], fun a -> Web_proxy_auto_disc a);
    (* Crowbar.Const End; *) (* charrua-core refusing to serialize this is legitimate, and it shouldn't expose it in the parsed output either; it's arguable that it shouldn't be exposed at all, along with Pad *)
    (* if we don't restrict "Unassigned" to stuff we don't know about,
     * we end up getting false negative results on the deserialize/serialize
     * equality test *)
    (* charrua-core discards unknown options, so don't include them *)
    (* unassigned; *)
  ]

let op : op Crowbar.gen =
  Crowbar.Map ([range 1], fun n -> int_to_op_exn @@ n+1)

let htype : htype Crowbar.gen = Crowbar.Const Dhcp_wire.Ethernet_10mb
let hlen = Crowbar.Const 6

let flags : flags Crowbar.gen = 
  Crowbar.Map ([range 1], function | 0 -> Broadcast | _n -> Dhcp_wire.Unicast)

let packet ?with_msgtype () : pkt Crowbar.gen =
  let msg_gen = match with_msgtype with
  | Some m -> Crowbar.Const m
  | None -> msgtype
  in
    Crowbar.Map ([
      macaddr; macaddr;
      ipv4; ipv4;
      uint16; uint16;
      op;
      htype; hlen;
      uint8;
      int32;
      uint16;
      flags;
      ipv4; ipv4; ipv4; ipv4;
      macaddr;
      bytes; bytes;
      msg_gen;
      Crowbar.List1 opt;
    ], fun srcmac dstmac srcip dstip srcport dstport op htype hlen hops xid secs
           flags ciaddr yiaddr siaddr giaddr chaddr raw_sname raw_file msg opt ->
           (* coercing the random sname and file into a correctly-sized fixed
            * buffer is a bit annoying, and additionally we need to handle the empty case *)
           let sname, file = Bytes.create 64, Bytes.create 128 in
           let is_null n =
             let non_null = ref false in
             Bytes.iter (fun i -> match !non_null, i with _, '\000' | true, _ -> ()
                                  | false, _ -> non_null := true) n;
             not !non_null
           in
           Bytes.fill sname 0 64 '\000';
           Bytes.fill file 0 64 '\000';
           Bytes.blit (Bytes.of_string raw_sname) 0 sname 0 (min 64 (String.length raw_sname));
           Bytes.blit (Bytes.of_string raw_file) 0 file 0 (min 128 (String.length raw_file));
           let sname = match is_null sname with | true -> "" | _ -> Bytes.to_string sname
           and file = match is_null file with | true -> "" | _ -> Bytes.to_string file
           in
           { srcmac = srcmac; dstmac; srcip; dstip; srcport; dstport;
             op; htype; hlen; hops; xid; secs; flags;
             ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
             options = (Message_type msg) :: opt; }
    )

let discovering_client : (Dhcp_client.t * Cstruct.t) Crowbar.gen =
  Crowbar.Map ([macaddr; List1 opt_code], fun m o ->
  Dhcp_client.create ~requests:o m)

let range_server : Dhcp_server.Config.t Crowbar.gen =
  Crowbar.Map ([macaddr; ipv4_prefix], fun m network ->
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
  Crowbar.add_test ~name:"no lease on fresh discovering_client" [discovering_client] @@ fun (c, _buf) ->
  Crowbar.check (match Dhcp_client.lease c with | Some _ -> false | None -> true)

let discovering_clients_ask_for_opt_code () =
  Crowbar.add_test ~name:"discovering_clients ask for the given option codes" [macaddr; List1 opt_code] @@ fun m o ->
  let (_c, b) = Dhcp_client.create ~requests:o m in
  let b = really_parse b in
  Crowbar.check_eq (find_parameter_requests b.options) (Some o)

let record_is_serializable () =
  Crowbar.add_test ~name:"record is serializable" [packet ()] @@ fun pkt ->
  ignore (buf_of_pkt pkt); Crowbar.check true

let serialize_deserialize () =
  let pp fmt pkt =
    Format.fprintf fmt "%s" @@ pkt_to_string pkt
  in
  Crowbar.add_test ~name:"records print/parse and are the same" [packet ()] @@ fun pkt ->
  let serialized = buf_of_pkt pkt in
    let deserialized = really_parse serialized in
    Crowbar.check_eq ~pp ~cmp:(fun a b -> String.compare (pkt_to_string a) (Dhcp_wire.pkt_to_string b))
    pkt deserialized

let xid_mismatch_always_noop () =
  Crowbar.add_test ~name:"input for other xids never gets a response"
    [discovering_client; packet ~with_msgtype:DHCPOFFER ()] @@ fun (discovering_client, dhcpdiscover) response ->
      let d = (really_parse dhcpdiscover) in
      Crowbar.guard (d.xid <> response.xid); (* no fun to make them equal if they already are *)
      let coerced = {response with xid = d.xid } in
      let coerced_response = buf_of_pkt coerced in
      let uneq_action = Dhcp_client.input discovering_client (buf_of_pkt response) in
      let coerced_action = Dhcp_client.input discovering_client coerced_response in
      Crowbar.guard (coerced_action <> `Noop);
      Crowbar.check_eq uneq_action `Noop

let one_message_no_lease () =
  Crowbar.add_test ~name:"one message doesn't get a lease" [discovering_client; packet ~with_msgtype:DHCPACK ()] @@ fun (discovering_client, _buf) message ->
  match Dhcp_client.input discovering_client (buf_of_pkt message) with
  | `Noop -> Crowbar.bad_test ()
  | `Response _ -> Crowbar.check true
  | `New_lease _ -> Crowbar.check false

let client_intelligible_by_server () =
  Crowbar.add_test ~name:"fresh client and server can communicate without sharing config"
  [range_server; discovering_client] @@ fun s (_c, client_output) ->
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
  [range_server; discovering_client] @@ fun s (c, send_me) ->
    let really_input s db buf time =
      match Input.input_pkt s db buf time with
      | Input.Silence | Input.Update _ | Input.Warning _ | Input.Error _ -> Crowbar.bad_test ()
      | Input.Reply (dhcpoffer, db) -> (dhcpoffer, db)
    in
    let err_no_response pkt = 
      Error (fun ppf () -> Crowbar.pp ppf "no response to %s" @@ pkt_to_string pkt)
    in
    let time = 0l in
    let dhcpdiscover = really_parse send_me in
    let (dhcpoffer, db) = really_input s (Lease.make_db ()) dhcpdiscover time in
    match Dhcp_client.input c (buf_of_pkt dhcpoffer) with
    | `Noop -> err_no_response dhcpoffer
    | `New_lease (_c, lease) ->
      Error (fun ppf () -> Crowbar.pp ppf "client thought dhcpoffer gave it a lease %s" @@ pkt_to_string lease)
    | `Response (c, dhcprequest) ->
      let dhcprequest = really_parse dhcprequest in
      let (dhcpack, _db) = really_input s db dhcprequest time in
      match Dhcp_client.input c (buf_of_pkt dhcpack) with
      | `Noop -> err_no_response dhcpack
      | `Response (_c, wat) ->
        Error (fun ppf () -> Crowbar.pp ppf "response to dhcpack: %s" @@ pkt_to_string (really_parse wat))
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
