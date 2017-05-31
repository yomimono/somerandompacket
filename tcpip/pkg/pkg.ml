#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
    Pkg.describe ~opams:[] "fuzz" @@ fun _ ->
    Ok [
            Pkg.bin "src/fuzz_ethif";
            Pkg.bin "src/fuzz_arpv4";
            Pkg.bin "src/fuzz_ipv4";
            Pkg.bin "src/fuzz_icmpv4";
            Pkg.bin "src/fuzz_tcp";
            Pkg.bin "src/fuzz_udp";
       ]
