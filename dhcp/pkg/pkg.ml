#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
    Pkg.describe ~opams:[] "omfgdhcpc" @@ fun _ ->
    Ok [
            Pkg.bin "src/omfgdhcpc";
       ]
