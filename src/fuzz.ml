let main ~f ~pp () =
  set_binary_mode_in stdin true;
  try
    match f @@ Cstruct.of_string @@ read_line () with
    | Ok (h, _p) -> Format.printf "%a" pp h
    | Error e -> Format.printf "%s" e
  with
  | End_of_file -> Printf.eprintf "No more input available, giving up"; exit 1
