module Macaddr = struct
  let to_crowbar : Macaddr.t Crowbar.gen =
  Crowbar.map Crowbar.[uint8; uint8; uint8; uint8; uint8; uint8] (fun a b c d e f ->
  Macaddr.make_local @@ function
    | 0 -> (a land 252)
    | 1 -> b | 2 -> c | 3 -> d | 4 -> e | _n -> f
  )
  include Macaddr
end
module Ipaddr = struct
  module V4 = struct
    type t = Ipaddr.V4.t
    let to_crowbar = Crowbar.map Crowbar.[int32] Ipaddr.V4.of_int32
    module Prefix = struct
      let to_crowbar =
        Crowbar.map Crowbar.[range 31; to_crowbar]
          (fun a b -> Ipaddr.V4.Prefix.make (a+1) b)
      include Ipaddr.V4.Prefix
    end
  end
  module V6 = Ipaddr.V6
end

let uint16 : Cstruct.uint16 Crowbar.gen =
  Crowbar.map Crowbar.[uint8; uint8] (fun u l -> (u lsl 4) + l)

let static_routes : (Ipaddr.V4.t * Ipaddr.V4.t) Crowbar.gen =
  Crowbar.map Crowbar.[Ipaddr.V4.to_crowbar; Ipaddr.V4.to_crowbar]
    (fun a b -> a, b)

type option_code = [%import: Dhcp_wire.option_code] [@@deriving crowbar]

let is_unassigned = function
  | Dhcp_wire.UNASSIGNED_84
  | Dhcp_wire.UNASSIGNED_96
  | Dhcp_wire.UNASSIGNED_102
  | Dhcp_wire.UNASSIGNED_103
  | Dhcp_wire.UNASSIGNED_104
  | Dhcp_wire.UNASSIGNED_105
  | Dhcp_wire.UNASSIGNED_106
  | Dhcp_wire.UNASSIGNED_107
  | Dhcp_wire.UNASSIGNED_108
  | Dhcp_wire.UNASSIGNED_109
  | Dhcp_wire.UNASSIGNED_110
  | Dhcp_wire.UNASSIGNED_111
  | Dhcp_wire.UNASSIGNED_115
  | Dhcp_wire.UNASSIGNED_126
  | Dhcp_wire.UNASSIGNED_127
  | Dhcp_wire.UNASSIGNED_143
  | Dhcp_wire.UNASSIGNED_147
  | Dhcp_wire.UNASSIGNED_148
  | Dhcp_wire.UNASSIGNED_149
  | Dhcp_wire.UNASSIGNED_161
  | Dhcp_wire.UNASSIGNED_162
  | Dhcp_wire.UNASSIGNED_163
  | Dhcp_wire.UNASSIGNED_164
  | Dhcp_wire.UNASSIGNED_165
  | Dhcp_wire.UNASSIGNED_166
  | Dhcp_wire.UNASSIGNED_167
  | Dhcp_wire.UNASSIGNED_168
  | Dhcp_wire.UNASSIGNED_169
  | Dhcp_wire.UNASSIGNED_170
  | Dhcp_wire.UNASSIGNED_171
  | Dhcp_wire.UNASSIGNED_172
  | Dhcp_wire.UNASSIGNED_173
  | Dhcp_wire.UNASSIGNED_174
  | Dhcp_wire.UNASSIGNED_178
  | Dhcp_wire.UNASSIGNED_179
  | Dhcp_wire.UNASSIGNED_180
  | Dhcp_wire.UNASSIGNED_181
  | Dhcp_wire.UNASSIGNED_182
  | Dhcp_wire.UNASSIGNED_183
  | Dhcp_wire.UNASSIGNED_184
  | Dhcp_wire.UNASSIGNED_185
  | Dhcp_wire.UNASSIGNED_186
  | Dhcp_wire.UNASSIGNED_187
  | Dhcp_wire.UNASSIGNED_188
  | Dhcp_wire.UNASSIGNED_189
  | Dhcp_wire.UNASSIGNED_190
  | Dhcp_wire.UNASSIGNED_191
  | Dhcp_wire.UNASSIGNED_192
  | Dhcp_wire.UNASSIGNED_193
  | Dhcp_wire.UNASSIGNED_194
  | Dhcp_wire.UNASSIGNED_195
  | Dhcp_wire.UNASSIGNED_196
  | Dhcp_wire.UNASSIGNED_197
  | Dhcp_wire.UNASSIGNED_198
  | Dhcp_wire.UNASSIGNED_199
  | Dhcp_wire.UNASSIGNED_200
  | Dhcp_wire.UNASSIGNED_201
  | Dhcp_wire.UNASSIGNED_202
  | Dhcp_wire.UNASSIGNED_203
  | Dhcp_wire.UNASSIGNED_204
  | Dhcp_wire.UNASSIGNED_205
  | Dhcp_wire.UNASSIGNED_206
  | Dhcp_wire.UNASSIGNED_207
  | Dhcp_wire.UNASSIGNED_214
  | Dhcp_wire.UNASSIGNED_215
  | Dhcp_wire.UNASSIGNED_216
  | Dhcp_wire.UNASSIGNED_217
  | Dhcp_wire.UNASSIGNED_218
  | Dhcp_wire.UNASSIGNED_219
  | Dhcp_wire.UNASSIGNED_222
  | Dhcp_wire.UNASSIGNED_223 -> true
  | _ -> false

let assigned_code_to_crowbar = Crowbar.map [option_code_to_crowbar]
    (fun code -> match is_unassigned code with
         false -> code | true -> Crowbar.bad_test ())

let unassigned_code_to_crowbar = Crowbar.map [option_code_to_crowbar]
    (fun code -> match is_unassigned code with
         true -> code | false -> Crowbar.bad_test ())


let unassigned : Dhcp_wire.dhcp_option Crowbar.gen =
  Crowbar.map Crowbar.[unassigned_code_to_crowbar; bytes] (fun a s ->
  Dhcp_wire.Unassigned (a, s)
    )

type client_id = [%import: Dhcp_wire.client_id] [@@deriving crowbar]
type msgtype = [%import: Dhcp_wire.msgtype] [@@deriving crowbar]
type dhcp_option = [%import: Dhcp_wire.dhcp_option] [@@deriving crowbar]

let dhcp_option_to_crowbar = Crowbar.map [dhcp_option_to_crowbar] (function
    | Unassigned _ -> Crowbar.bad_test ()
    | opt -> opt
  )
type op = [%import: Dhcp_wire.op] [@@deriving crowbar]

let htype : Dhcp_wire.htype Crowbar.gen = Crowbar.const Dhcp_wire.Ethernet_10mb
let hlen = Crowbar.const 6

type flags = [%import: Dhcp_wire.flags] [@@deriving crowbar]

let packet ?with_msgtype () : Dhcp_wire.pkt Crowbar.gen =
  let msg_gen = match with_msgtype with
  | Some m -> Crowbar.const m
  | None -> msgtype_to_crowbar
  in
    Crowbar.map Crowbar.[
      Macaddr.to_crowbar; Macaddr.to_crowbar;
      Ipaddr.V4.to_crowbar; Ipaddr.V4.to_crowbar;
      uint16; uint16;
      op_to_crowbar;
      htype; hlen;
      uint8;
      int32;
      uint16;
      flags_to_crowbar;
      Ipaddr.V4.to_crowbar; Ipaddr.V4.to_crowbar; Ipaddr.V4.to_crowbar; Ipaddr.V4.to_crowbar;
      Macaddr.to_crowbar;
      bytes; bytes;
      msg_gen;
      list1 dhcp_option_to_crowbar;
    ] (fun srcmac dstmac srcip dstip srcport dstport op htype hlen hops xid secs
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
           Bytes.fill file 0 128 '\000';
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
