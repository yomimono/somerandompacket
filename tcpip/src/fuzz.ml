let get_input () =
  set_binary_mode_in stdin true;
  let b = Buffer.create 1000 in
  let buf = Bytes.create 1000 in
  try
    while true do
      let got = input stdin buf 0 (Bytes.length buf) in
      if got = 0 then raise End_of_file;
      assert (got > 0);
      Buffer.add_subbytes b buf 0 got
    done;
    assert false
  with End_of_file ->
    Buffer.contents b

let main ~f ~pp () =
   match f @@ Cstruct.of_string @@ get_input () with
   | Ok (h, _p) -> Format.printf "%a" pp h
   | Error e -> Format.printf "%s" e
