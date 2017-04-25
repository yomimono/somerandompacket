let macaddr : Macaddr.t Crowbar.gen =
  Crowbar.Map (Crowbar.[uint8; uint8; uint8; uint8; uint8; uint8], fun a b c d e f ->
  Macaddr.make_local @@ function
    | 0 -> (a land 252)
    | 1 -> b | 2 -> c | 3 -> d | 4 -> e | _n -> f
  )

let uint16 : Cstruct.uint16 Crowbar.gen =
  Crowbar.Map (Crowbar.[uint8; uint8], fun u l -> (u lsl 4) + l)

let ipv4 : Ipaddr.V4.t Crowbar.gen =
  Crowbar.Map (Crowbar.[int32], Ipaddr.V4.of_int32)

let ipv4_prefix : Ipaddr.V4.Prefix.t Crowbar.gen =
  Crowbar.Map (Crowbar.[range 31; ipv4], fun a b -> Ipaddr.V4.Prefix.make (a+1) b)

let static_routes : (Ipaddr.V4.t * Ipaddr.V4.t) Crowbar.gen =
  Crowbar.Map (Crowbar.[ipv4; ipv4], fun a b -> a, b)

let opt_code : Dhcp_wire.option_code Crowbar.gen =
  Crowbar.Map (Crowbar.[uint8], Crowbar.or_bad_test Dhcp_wire.int_to_option_code)

let unassigned_code : Dhcp_wire.option_code Crowbar.gen =
 Crowbar.Choose [
    Crowbar.Const Dhcp_wire.UNASSIGNED_84;
    Crowbar.Const Dhcp_wire.UNASSIGNED_96;
    Crowbar.Const Dhcp_wire.UNASSIGNED_102;
    Crowbar.Const Dhcp_wire.UNASSIGNED_103;
    Crowbar.Const Dhcp_wire.UNASSIGNED_104;
    Crowbar.Const Dhcp_wire.UNASSIGNED_105;
    Crowbar.Const Dhcp_wire.UNASSIGNED_106;
    Crowbar.Const Dhcp_wire.UNASSIGNED_107;
    Crowbar.Const Dhcp_wire.UNASSIGNED_108;
    Crowbar.Const Dhcp_wire.UNASSIGNED_109;
    Crowbar.Const Dhcp_wire.UNASSIGNED_110;
    Crowbar.Const Dhcp_wire.UNASSIGNED_111;
    Crowbar.Const Dhcp_wire.UNASSIGNED_115;
    Crowbar.Const Dhcp_wire.UNASSIGNED_126;
    Crowbar.Const Dhcp_wire.UNASSIGNED_127;
    Crowbar.Const Dhcp_wire.UNASSIGNED_143;
    Crowbar.Const Dhcp_wire.UNASSIGNED_147;
    Crowbar.Const Dhcp_wire.UNASSIGNED_148;
    Crowbar.Const Dhcp_wire.UNASSIGNED_149;
    Crowbar.Const Dhcp_wire.UNASSIGNED_161;
    Crowbar.Const Dhcp_wire.UNASSIGNED_162;
    Crowbar.Const Dhcp_wire.UNASSIGNED_163;
    Crowbar.Const Dhcp_wire.UNASSIGNED_164;
    Crowbar.Const Dhcp_wire.UNASSIGNED_165;
    Crowbar.Const Dhcp_wire.UNASSIGNED_166;
    Crowbar.Const Dhcp_wire.UNASSIGNED_167;
    Crowbar.Const Dhcp_wire.UNASSIGNED_168;
    Crowbar.Const Dhcp_wire.UNASSIGNED_169;
    Crowbar.Const Dhcp_wire.UNASSIGNED_170;
    Crowbar.Const Dhcp_wire.UNASSIGNED_171;
    Crowbar.Const Dhcp_wire.UNASSIGNED_172;
    Crowbar.Const Dhcp_wire.UNASSIGNED_173;
    Crowbar.Const Dhcp_wire.UNASSIGNED_174;
    Crowbar.Const Dhcp_wire.UNASSIGNED_178;
    Crowbar.Const Dhcp_wire.UNASSIGNED_179;
    Crowbar.Const Dhcp_wire.UNASSIGNED_180;
    Crowbar.Const Dhcp_wire.UNASSIGNED_181;
    Crowbar.Const Dhcp_wire.UNASSIGNED_182;
    Crowbar.Const Dhcp_wire.UNASSIGNED_183;
    Crowbar.Const Dhcp_wire.UNASSIGNED_184;
    Crowbar.Const Dhcp_wire.UNASSIGNED_185;
    Crowbar.Const Dhcp_wire.UNASSIGNED_186;
    Crowbar.Const Dhcp_wire.UNASSIGNED_187;
    Crowbar.Const Dhcp_wire.UNASSIGNED_188;
    Crowbar.Const Dhcp_wire.UNASSIGNED_189;
    Crowbar.Const Dhcp_wire.UNASSIGNED_190;
    Crowbar.Const Dhcp_wire.UNASSIGNED_191;
    Crowbar.Const Dhcp_wire.UNASSIGNED_192;
    Crowbar.Const Dhcp_wire.UNASSIGNED_193;
    Crowbar.Const Dhcp_wire.UNASSIGNED_194;
    Crowbar.Const Dhcp_wire.UNASSIGNED_195;
    Crowbar.Const Dhcp_wire.UNASSIGNED_196;
    Crowbar.Const Dhcp_wire.UNASSIGNED_197;
    Crowbar.Const Dhcp_wire.UNASSIGNED_198;
    Crowbar.Const Dhcp_wire.UNASSIGNED_199;
    Crowbar.Const Dhcp_wire.UNASSIGNED_200;
    Crowbar.Const Dhcp_wire.UNASSIGNED_201;
    Crowbar.Const Dhcp_wire.UNASSIGNED_202;
    Crowbar.Const Dhcp_wire.UNASSIGNED_203;
    Crowbar.Const Dhcp_wire.UNASSIGNED_204;
    Crowbar.Const Dhcp_wire.UNASSIGNED_205;
    Crowbar.Const Dhcp_wire.UNASSIGNED_206;
    Crowbar.Const Dhcp_wire.UNASSIGNED_207;
    Crowbar.Const Dhcp_wire.UNASSIGNED_214;
    Crowbar.Const Dhcp_wire.UNASSIGNED_215;
    Crowbar.Const Dhcp_wire.UNASSIGNED_216;
    Crowbar.Const Dhcp_wire.UNASSIGNED_217;
    Crowbar.Const Dhcp_wire.UNASSIGNED_218;
    Crowbar.Const Dhcp_wire.UNASSIGNED_219;
    Crowbar.Const Dhcp_wire.UNASSIGNED_222;
    Crowbar.Const Dhcp_wire.UNASSIGNED_223;
  ]

let unassigned : Dhcp_wire.dhcp_option Crowbar.gen =
  Crowbar.Map (Crowbar.[unassigned_code; bytes], fun a s ->
  Dhcp_wire.Unassigned (a, s)
)

let client_id : Dhcp_wire.client_id Crowbar.gen =
  Crowbar.Choose [
    Crowbar.Map (Crowbar.[macaddr], fun a -> Dhcp_wire.Hwaddr a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Id a)
  ]

let msgtype : Dhcp_wire.msgtype Crowbar.gen =
  Crowbar.Map (Crowbar.[range 14], fun a -> Crowbar.or_bad_test Dhcp_wire.int_to_msgtype (a+1))

let opt : Dhcp_wire.dhcp_option Crowbar.gen =
 Crowbar.Choose [
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Subnet_mask a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Time_offset a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Routers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Time_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Name_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Dns_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Log_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Cookie_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Lpr_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Impress_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Rsclocation_servers a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Hostname a);
    Crowbar.Map (Crowbar.[uint16], fun a -> Dhcp_wire.Bootfile_size a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Merit_dumpfile a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Domain_name a);
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Swap_server a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Root_path a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Extension_path a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Ipforwarding a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Nlsr a);
    Crowbar.Map (Crowbar.[List1 ipv4_prefix], fun a -> Dhcp_wire.Policy_filters a);
    Crowbar.Map (Crowbar.[uint16], fun a -> Dhcp_wire.Max_datagram a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Default_ip_ttl a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Pmtu_ageing_timo a);
    Crowbar.Map (Crowbar.[List1 uint16], fun a -> Dhcp_wire.Pmtu_plateau_table a);
    Crowbar.Map (Crowbar.[uint16], fun a -> Dhcp_wire.Interface_mtu a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.All_subnets_local a);
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Broadcast_addr a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Perform_mask_discovery a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Mask_supplier a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Perform_router_disc a);
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Router_sol_addr a);
    Crowbar.Map (Crowbar.[List1 static_routes], fun a -> Dhcp_wire.Static_routes a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Trailer_encapsulation a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Arp_cache_timo a);
    Crowbar.Map (Crowbar.[bool], fun a -> Dhcp_wire.Ethernet_encapsulation a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Tcp_default_ttl a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Tcp_keepalive_interval a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Tcp_keepalive_garbage a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Nis_domain a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Nis_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Ntp_servers a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Vendor_specific a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Netbios_name_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Netbios_datagram_distrib_servers a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Netbios_node a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Netbios_scope a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Xwindow_font_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Xwindow_display_managers a);
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Request_ip a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Ip_lease_time a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Option_overload a);
    Crowbar.Map (Crowbar.[msgtype], fun a -> Dhcp_wire.Message_type a);
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Server_identifier a);
    Crowbar.Map (Crowbar.[List1 opt_code], fun a -> Dhcp_wire.Parameter_requests a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Message a);
    Crowbar.Map (Crowbar.[uint16], fun a -> Dhcp_wire.Max_message a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Renewal_t1 a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Rebinding_t2 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Vendor_class_id a);
    Crowbar.Map (Crowbar.[client_id], fun a -> Dhcp_wire.Client_id a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Netware_ip_domain a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Netware_ip_option a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Nis_plus_domain a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Nis_plus_servers a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Tftp_server_name a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Bootfile_name a);
    Crowbar.Map (Crowbar.[List ipv4], fun a -> Dhcp_wire.Mobile_ip_home_agent a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Smtp_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Pop3_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Nntp_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Www_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Finger_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Irc_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Streettalk_servers a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Streettalk_da a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.User_class a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Directory_agent a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Service_scope a);
    Crowbar.Const Dhcp_wire.Rapid_commit;
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Client_fqdn a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Relay_agent_information a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Isns a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Nds_servers a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Nds_tree_name a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Nds_context a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Bcmcs_controller_domain_name_list a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Bcmcs_controller_ipv4_addrs a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Authentication a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Client_last_transaction_time a);
    Crowbar.Map (Crowbar.[List1 ipv4], fun a -> Dhcp_wire.Associated_ips a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Client_system a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Client_ndi a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Ldap a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Uuid_guid a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.User_auth a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Geoconf_civic a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pcode a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Tcode a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Netinfo_address a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Netinfo_tag a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Url a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Auto_config a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Name_service_search a);
    Crowbar.Map (Crowbar.[ipv4], fun a -> Dhcp_wire.Subnet_selection a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Domain_search a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Sip_servers a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Classless_static_route a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Ccc a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Geoconf a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Vi_vendor_class a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Vi_vendor_info a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_128 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_129 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_130 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_131 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_132 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_133 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_134 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pxe_135 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Pana_agent a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.V4_lost a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Capwap_ac_v4 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Ipv4_address_mos a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Ipv4_fqdn_mos a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Sip_ua_domains a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Ipv4_address_andsf a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Geolock a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Forcenew_nonce_capable a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Rdnss_selection a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Misc_150 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Status_code a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Absolute_time a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Start_time_of_state a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Query_start_time a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Query_end_time a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Dhcp_state a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Data_source a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.V4_pcp_server a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.V4_portparams a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Dhcp_captive_portal a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Etherboot_175 a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Ip_telefone a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Etherboot_177 a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Pxe_linux a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Configuration_file a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Path_prefix a);
    Crowbar.Map (Crowbar.[int32], fun a -> Dhcp_wire.Reboot_time a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Option_6rd a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.V4_access_domain a);
    Crowbar.Map (Crowbar.[uint8], fun a -> Dhcp_wire.Subnet_allocation a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Virtual_subnet_selection a);
    Crowbar.Map (Crowbar.[bytes], fun a -> Dhcp_wire.Web_proxy_auto_disc a);
    (* if we don't restrict "Unassigned" to stuff we don't know about,
     * we end up getting false negative results on the deserialize/serialize
     * equality test *)
    (* charrua-core discards unknown options, so don't include them *)
  ]

let op : Dhcp_wire.op Crowbar.gen =
  Crowbar.Map (Crowbar.[range 1], fun n -> Dhcp_wire.int_to_op_exn @@ n+1)

let htype : Dhcp_wire.htype Crowbar.gen = Crowbar.Const Dhcp_wire.Ethernet_10mb
let hlen = Crowbar.Const 6

let flags : Dhcp_wire.flags Crowbar.gen =
  Crowbar.Map (Crowbar.[range 1], function
          | 0 -> Dhcp_wire.Broadcast
          | _n -> Dhcp_wire.Unicast)

let packet ?with_msgtype () : Dhcp_wire.pkt Crowbar.gen =
  let msg_gen = match with_msgtype with
  | Some m -> Crowbar.Const m
  | None -> msgtype
  in
    Crowbar.Map (Crowbar.[
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
      List1 opt;
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
           Dhcp_wire.{ srcmac = srcmac; dstmac; srcip; dstip; srcport; dstport;
             op; htype; hlen; hops; xid; secs; flags;
             ciaddr; yiaddr; siaddr; giaddr; chaddr; sname; file;
             options = (Message_type msg) :: opt; }
    )
